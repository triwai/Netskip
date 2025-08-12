@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%"

python -m pip install --upgrade pip
if errorlevel 1 (
  echo [WARN] pip のアップグレードに失敗しましたが、続行します。
)

python -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] 依存パッケージのインストールに失敗しました。
  goto :end_with_error
)

echo.
echo [OK] パッケージのインストールが完了しました。
goto :end

:end_with_error
echo.
echo セットアップに失敗しました。ネットワークやプロキシ設定を確認のうえ、再実行してください。
exit /b 1

:end
popd
endlocal