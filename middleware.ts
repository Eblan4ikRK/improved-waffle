// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';

// --- НАСТРОЙКИ ---

// 1. Список стран для блокировки (ISO 3166-1 alpha-2)
const BLOCKED_COUNTRIES: string[] = [
  'VN', 'CN', 'IN', 'PK', 'BR', 'ID', 'TH', 'TR', 'EG', 'SC', 'IR', 'NG', 'RU'
];

// 2. WHITELIST: Список разрешенных User-Agent. Пропускаем только их.
// Расширен для лучшей совместимости (добавлены 'Mozilla' для браузеров).
const ALLOWED_USER_AGENTS: string[] = [
  'Mozilla',  // Общий для многих браузеров (Chrome, Firefox, etc.)
  'Chrome',   // Google Chrome, Brave, и другие на основе Chromium
  'Firefox',  // Mozilla Firefox
  'Safari',   // Apple Safari
  'Edg',      // Microsoft Edge
  'OPR',      // Opera
  // Поисковые боты для SEO
  'Googlebot',
  'Bingbot',
  'Slurp',    // Yahoo
  'DuckDuckBot',
  'YandexBot',
];

// Optional: BLACKLIST для known bad agents (активируйте, если whitelist слишком строгий)
// const BLOCKED_USER_AGENTS: string[] = ['curl', 'python-requests', 'bot', 'spider'];

// 3. Ограничение для ОДНОГО IP-адреса (Rate Limit)
const INDIVIDUAL_RATE_LIMIT = { requests: 10, window: '10 s' } as const;

// 4. Порог для определения атаки и отправки уведомления
// Это burst-detection (пиковые нагрузки). Для sustained атак уменьшите window или используйте sliding ratelimit.
const ATTACK_THRESHOLD = 10000; // 10,000 запросов
const ATTACK_TIME_WINDOW_SECONDS = 60; // за 60 секунд

// --- КОНЕЦ НАСТРОЕК ---

// Инициализация Redis
let redis: Redis | null = null;
let ratelimit: Ratelimit | null = null;

// Optional: Глобальный rate limit для всех запросов (активируйте для блокировки при атаке)
// let globalRatelimit: Ratelimit | null = null;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });

  ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(INDIVIDUAL_RATE_LIMIT.requests, INDIVIDUAL_RATE_LIMIT.window),
    analytics: true,
    prefix: 'ratelimit',
  });

  // globalRatelimit = new Ratelimit({
  //   redis,
  //   limiter: Ratelimit.slidingWindow(ATTACK_THRESHOLD, `${ATTACK_TIME_WINDOW_SECONDS} s`),
  //   analytics: true,
  //   prefix: 'global',
  // });
} else {
  console.warn('Upstash Redis environment variables not found. Key security features are disabled.');
}

// Основная функция Middleware
export async function middleware(request: NextRequest) {
  if (!redis || !ratelimit) {
    return NextResponse.next();
  }

  // Извлечение IP из заголовков (для совместимости с TypeScript и разными средами)
  const ip = (request.headers.get('x-forwarded-for')?.split(',').shift()?.trim() ||
              request.headers.get('x-real-ip') ||
              '127.0.0.1') ?? '127.0.0.1';

  const country = request.geo?.country;
  const userAgent = request.headers.get('user-agent') || '';

  // 1. Считаем ВСЕ входящие запросы для детекции атак (в начале)
  const { totalRequests, blockedRequests } = await getAttackCounters(redis);

  // 2. Проверка на атаку (на все запросы, даже заблокированные позже)
  if (totalRequests > ATTACK_THRESHOLD) {
    const notificationSent = await redis.get('notification_sent_flag');
    if (!notificationSent) {
      const passedRequests = totalRequests - blockedRequests; // Приближенно
      const attackStrength = (totalRequests / ATTACK_TIME_WINDOW_SECONDS).toFixed(1);

      const message = `🚨 *Обнаружена атака на сайт!* 🚨
      
- *Сила атаки:* ~${attackStrength} запросов/сек
- *Всего запросов за ~${ATTACK_TIME_WINDOW_SECONDS} сек:* ${totalRequests}
- *Заблокировано (Geo/UA/RateLimit):* ${blockedRequests}
- *Прошло на сайт:* ${passedRequests}
      
Приняты автоматические меры по ограничению.`;

      await sendTelegramMessage(message);
      await redis.set('notification_sent_flag', 'true', { ex: ATTACK_TIME_WINDOW_SECONDS });
    }

    // Optional: Авто-блок при атаке (раскомментируйте)
    // return new NextResponse('Site under attack. Please try later.', { status: 503 });
  }

  // === ЦЕПОЧКА ПРОВЕРОК (после детекции, чтобы считать все) ===

  // 3. Блокировка по стране
  if (country && BLOCKED_COUNTRIES.includes(country)) {
    await incrementBlockedCounter(redis);
    return new NextResponse(`Access from country ${country} is denied.`, { status: 403 });
  }

  // 4. Блокировка по User-Agent (whitelist)
  const isAllowedUserAgent = ALLOWED_USER_AGENTS.some(agent => userAgent.includes(agent));
  if (!isAllowedUserAgent) {
    // Optional: Дополнительно blacklist (раскомментируйте)
    // const isBlockedUserAgent = BLOCKED_USER_AGENTS.some(agent => userAgent.toLowerCase().includes(agent));
    // if (isBlockedUserAgent) {
    await incrementBlockedCounter(redis);
    return new NextResponse('Your browser or bot is not allowed.', { status: 403 });
    // }
  }

  // 5. Индивидуальный Rate Limit по IP
  const { success } = await ratelimit.limit(ip);
  if (!success) {
    await incrementBlockedCounter(redis);
    return new NextResponse('Too many requests. Please try again later.', { status: 429 });
  }

  // Optional: Глобальный rate limit (раскомментируйте для активации)
  // if (globalRatelimit) {
  //   const { success: globalSuccess } = await globalRatelimit.limit('global');
  //   if (!globalSuccess) {
  //     await incrementBlockedCounter(redis);
  //     return new NextResponse('Site under heavy load. Please try again later.', { status: 429 });
  //   }
  // }

  return NextResponse.next();
}

// --- Вспомогательные функции ---

async function getAttackCounters(redis: Redis) {
  const totalKey = 'attack:total';
  const blockedKey = 'attack:blocked';

  const pipe = redis.pipeline();
  pipe.incr(totalKey);
  pipe.expire(totalKey, ATTACK_TIME_WINDOW_SECONDS, 'NX');
  pipe.get(blockedKey);
  pipe.expire(blockedKey, ATTACK_TIME_WINDOW_SECONDS, 'NX');

  const results = await pipe.exec();
  if (!results) {
    console.error('Redis pipeline failed in getAttackCounters');
    return { totalRequests: 0, blockedRequests: 0 };
  }

  const totalRequests = results[0] as number;
  const blockedStr = results[2] as string | null;

  return {
    totalRequests,
    blockedRequests: parseInt(blockedStr ?? '0', 10),
  };
}

async function incrementBlockedCounter(redis: Redis) {
  const blockedKey = 'attack:blocked';

  const pipe = redis.pipeline();
  pipe.incr(blockedKey);
  pipe.expire(blockedKey, ATTACK_TIME_WINDOW_SECONDS, 'NX');
  await pipe.exec().catch(err => console.error('Failed to increment blocked counter:', err));
}

async function sendTelegramMessage(text: string) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.warn('Telegram credentials are not set. Cannot send notification.');
    return;
  }

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
    });
    if (!response.ok) {
      console.error('Telegram API error:', await response.text());
    }
  } catch (error) {
    console.error('Failed to send Telegram message:', error);
  }
}

// --- КОНФИГУРАЦИЯ ---
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
