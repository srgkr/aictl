Репозиторий являетя форком [PT Application Inspector CLI control](https://github.com/POSIdev-community/aictl/).

## Изменения:
* ~~Добавлена поддержка формата aiproj версии 1.9 для PTAI_VERSION 5.4.0.60000 и выше~~ (неактуально)
* Добавлен показ полной статистики сканирования в соответствии с ScanStatisticModel в API (необходим для проверки более точного состояния после сканирования в версии 5.4.0.60000 в CI/CD для корректировки состояния когда при успешном "Done" возвращается счетчики FilesScanned = 0, FilesTotal > 0)
* Исправлена ошибка для запроса отчета в XML формате
* Исправлен недочёт в выводе scan await

---

## aictl
PT Application Inspector CLI control
___
### Documentation

- [Command reference](doc/aictl.md)
- [Migration: aisa → aictl](doc/migration/aisa-to-aictl.md)
- [Migration: ptai-cli-plugin → aictl](doc/migration/ptai-cli-plugin-to-aictl.md)
- [Gap analysis](doc/migration/gap-analysis.md)

### E2E tests

End-to-end tests run the base pipeline from [`examples/base-pipeline.sh`](examples/base-pipeline.sh) against external AIE stands (5.4 and 6.0).

**Setup:**

```bash
make e2e-config
# Edit tests/e2e/stands.local.yaml — set url and token for each stand
make test-e2e
```

**Run one stand:**

```bash
go test -tags=e2e -v -run 'AIE_5\.4' ./tests/e2e/...
```

Config path override: `AICTL_E2E_CONFIG=/path/to/stands.yaml`. Binary override: `AICTL_BIN=/path/to/aictl`.

Without `stands.local.yaml`, e2e tests are skipped; `go test ./...` does not run them (build tag `e2e`).
