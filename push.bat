@echo off
echo ==============================
echo 🚀 GitHub Auto Push Script
echo ==============================

REM التحقق من وجود Git
where git >nul 2>nul
if errorlevel 1 (
    echo ❌ Git غير مثبت على جهازك.
    pause
    exit /b
)

REM التحقق أنك داخل مستودع
if not exist ".git" (
    echo ❌ هذا المجلد ليس مستودع Git.
    pause
    exit /b
)

REM إضافة جميع الملفات
git add .

REM إنشاء commit برسالة
set /p msg="اكتب رسالة الـ commit (أو اضغط Enter لاستخدام الرسالة الافتراضية): "
if "%msg%"=="" (
    git commit -m "update project"
) else (
    git commit -m "%msg%"
)

REM التحقق إذا نجح الكوميت
if errorlevel 1 (
    echo ⚠️ لا توجد تغييرات جديدة لرفعها.
    pause
    exit /b
)

REM محاولة الرفع
git push origin main
if errorlevel 1 (
    echo ⚠️ فشل الرفع، سيتم استخدام force push...
    git push origin main --force
)

echo ==============================
echo ✅ تم رفع التغييرات إلى GitHub
echo ==============================
pause
