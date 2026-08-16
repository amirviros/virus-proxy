#!/data/data/com.termux/files/usr/bin/bash

echo "🔧 شروع ساخت فایل worker.js سالم..."
echo "========================================"

# تعیین نام فایل جدید
NEW_FILE="worker.fixed.js"
BACKUP_FILE="worker.backup.$(date +%s).js"

# پشتیبان‌گیری
if [ -f "worker.js" ]; then
    echo "📁 پشتیبان‌گیری از فایل فعلی..."
    cp worker.js "$BACKUP_FILE"
    echo "✅ پشتیبان در $BACKUP_FILE ذخیره شد"
fi

# پیدا کردن خط شروع کد جاوااسکریپت
START_LINE=$(grep -n "import{AsyncLocalStorage" worker.js | head -1 | cut -d: -f1)

if [ -z "$START_LINE" ]; then
    echo "⚠️ الگوی 'import{AsyncLocalStorage' پیدا نشد، جستجوی 'import'..."
    START_LINE=$(grep -n "^import" worker.js | head -1 | cut -d: -f1)
fi

if [ -z "$START_LINE" ]; then
    echo "❌ خط شروع کد جاوااسکریپت پیدا نشد!"
    exit 1
fi

echo "✅ خط شروع کد: $START_LINE"

# استخراج کد جاوااسکریپت
echo "📝 استخراج کد جاوااسکریپت..."
tail -n +$START_LINE worker.js > "$NEW_FILE"

# بررسی فایل جدید
if [ -f "$NEW_FILE" ] && [ $(wc -c < "$NEW_FILE") -gt 100000 ]; then
    echo "✅ فایل جدید ساخته شد: $NEW_FILE"
    echo "📏 حجم: $(wc -c < "$NEW_FILE") بایت"
    
    # نمایش چند خط اول
    echo "📝 ۵ خط اول فایل جدید:"
    head -n 5 "$NEW_FILE"
    
    # بررسی وجود export default
    if grep -q "export default" "$NEW_FILE"; then
        echo "✅ فایل جدید حاوی 'export default' است."
    else
        echo "⚠️ فایل جدید فاقد 'export default' است."
    fi
    
    # بررسی وجود تابع fetch
    if grep -q "async fetch" "$NEW_FILE"; then
        echo "✅ فایل جدید حاوی تابع fetch است."
    else
        echo "⚠️ فایل جدید فاقد تابع fetch است."
    fi
else
    echo "❌ ساخت فایل جدید ناموفق بود."
    exit 1
fi

echo "========================================"
echo "🎯 عملیات کامل شد. فایل جدید: $NEW_FILE"
echo "💡 می‌توانید این فایل را به گیت‌هاب آپلود کنید."
