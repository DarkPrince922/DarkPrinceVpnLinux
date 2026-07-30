package engine

import (
	"fmt"
	"os"
	"path/filepath"
)

// Конфиги панели часто содержат правила geoip:/geosite:. Для них ядру нужны
// файлы geoip.dat и geosite.dat, и без них оно отказывается стартовать
// целиком — не игнорирует правило, а роняет весь конфиг. Каталог с файлами
// ядро ищет по переменной XRAY_LOCATION_ASSET.
const assetEnv = "XRAY_LOCATION_ASSET"

// GeodataFiles — имена файлов, которые ищет ядро.
var GeodataFiles = []string{"geoip.dat", "geosite.dat"}

// SetupGeodata указывает ядру каталог с геоданными и сообщает, полон ли он.
// Отсутствие файлов не мешает запуску, пока подписка не пользуется
// правилами geoip:/geosite:, поэтому это не ошибка, а предупреждение.
func SetupGeodata(dir string) (missing []string, err error) {
	if dir == "" {
		return nil, fmt.Errorf("каталог геоданных не задан")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("каталог геоданных %s недоступен: %w", dir, err)
	}
	if err := os.Setenv(assetEnv, dir); err != nil {
		return nil, err
	}
	for _, name := range GeodataFiles {
		if _, statErr := os.Stat(filepath.Join(dir, name)); statErr != nil {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

// GeodataDir возвращает каталог, в котором ядро сейчас ищет геоданные.
func GeodataDir() string {
	return os.Getenv(assetEnv)
}
