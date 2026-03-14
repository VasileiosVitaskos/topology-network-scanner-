@echo off
echo ============================================
echo  Topo Scanner v7 - File Installation
echo ============================================
echo.

echo [Engine - Bug fixes + optimization]
copy /Y graph_builder.py  ..\backend\engine\graph_builder.py
copy /Y scanner.py         ..\backend\engine\scanner.py
echo.

echo [Config - Safe sensor limits]
copy /Y domains.yaml       ..\backend\config\domains.yaml
copy /Y requirements.txt   ..\backend\requirements.txt
echo.

echo [Frontend - New UI]
copy /Y App.css             ..\frontend\src\App.css
copy /Y App.js              ..\frontend\src\App.js
copy /Y AlertPanel.js       ..\frontend\src\components\AlertPanel.js
copy /Y ChatAssistant.js    ..\frontend\src\components\ChatAssistant.js
copy /Y DeviceConnector.js  ..\frontend\src\components\DeviceConnector.js
copy /Y NetworkGraph.js     ..\frontend\src\components\NetworkGraph.js
copy /Y ScanHistory.js      ..\frontend\src\components\ScanHistory.js
copy /Y TopologyManager.js  ..\frontend\src\components\TopologyManager.js
copy /Y DatasetSelector.js  ..\frontend\src\components\DatasetSelector.js
copy /Y api.js              ..\frontend\src\services\api.js
echo.

echo [Scripts]
copy /Y validate_engine.py  ..\scripts\validate_engine.py
echo.

echo [README]
copy /Y README.md           ..\README.md
echo.

echo ============================================
echo  Done. Now run:
echo    pip install -r backend\requirements.txt
echo    docker-compose up --build
echo ============================================
pause
