package awg

// Diff — расхождение одного параметра между файлом и рантаймом.
type Diff struct {
	Key     string `json:"key"`
	File    string `json:"file"`
	Runtime string `json:"runtime"`
}

// VerifyResult — итог сверки 12 параметров обфускации.
type VerifyResult struct {
	OK      bool              `json:"ok"`
	Matched int               `json:"matched"`
	Total   int               `json:"total"`
	File    map[string]string `json:"file"`
	Runtime map[string]string `json:"runtime"`
	Diffs   []Diff            `json:"diffs"`
}

// Verify сравнивает обфускацию из конфига и из дампа. Для чистого WireGuard (дамп без AWG-полей)
// результат OK только если и в файле параметров нет.
func Verify(c *Conf, d *InterfaceDump) VerifyResult {
	file := c.Obfuscation()
	rt := d.Obfuscation12()
	res := VerifyResult{File: file, Runtime: rt, Total: len(ObfKeys)}
	for _, k := range ObfKeys {
		if sameObf(file[k], rt[k]) {
			res.Matched++
			continue
		}
		res.Diffs = append(res.Diffs, Diff{Key: k, File: file[k], Runtime: rt[k]})
	}
	res.OK = len(res.Diffs) == 0
	return res
}

// sameObf сравнивает параметр в файле и в рантайме, считая ноль и отсутствие одним состоянием.
//
// Ядро хранит незаданный параметр нулём и таким отдаёт его в дампе, а в конфиге строки просто
// нет. Пока эти два вида записи считались разными, служебный интерфейс (в файле нет S3 и S4,
// в рантайме нули) давал 10/12 и красил весь сервер в «поломку», хотя настроен ровно как файл.
// Сравнение — единственное место, где ноль приравнивается к пустому: в выдаваемом клиенту конфиге
// строка «S3 = 0» остаётся как есть.
func sameObf(file, runtime string) bool {
	return zeroAsEmpty(file) == zeroAsEmpty(runtime)
}

func zeroAsEmpty(v string) string {
	if v == "0" {
		return ""
	}
	return v
}
