// یک پروکسی ساده که درخواست‌ها را به مقصد دلخواه هدایت می‌کند
// بدون نیاز به تنظیمات اضافی، فقط کافی است این کد را در Worker خود آپلود کنید.

const TARGET_BASE_URL = 'https://example.com'; // آدرس سرور مقصد را اینجا تغییر دهید

async function handleRequest(request) {
    const url = new URL(request.url);
    const targetUrl = new URL(url.pathname + url.search, TARGET_BASE_URL);

    // کپی کردن هدرهای درخواست (به جز هدرهای میزبان و بعضی موارد خاص)
    const headers = new Headers(request.headers);
    headers.set('Host', targetUrl.hostname);
    // حذف هدرهای مربوط به Cloudflare برای جلوگیری از خطا
    headers.delete('cf-connecting-ip');
    headers.delete('cf-ray');
    headers.delete('cf-request-id');

    // ارسال درخواست به سرور مقصد
    const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.body,
        redirect: 'follow'
    });

    // بازگرداندن پاسخ با هدرهای مناسب
    const responseHeaders = new Headers(response.headers);
    // اجازه دادن به CORS در صورت نیاز
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type');

    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
    });
}

// مدیریت درخواست‌های OPTIONS برای CORS
function handleOptions(request) {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400',
        }
    });
}

addEventListener('fetch', event => {
    const request = event.request;
    if (request.method === 'OPTIONS') {
        event.respondWith(handleOptions(request));
    } else {
        event.respondWith(handleRequest(request));
    }
});