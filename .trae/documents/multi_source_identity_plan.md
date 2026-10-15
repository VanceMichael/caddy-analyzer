# 多输入来源身份（per-source identity）实施计划

## Repository Research

现状（已核对代码）：

- 来源解析：`reader.ParseSource`（[reader.go](file:///Users/vance/project/mineProject/swe/09101503/project-03/pkg/reader/reader.go#L52-L70)）只区分 type/path；`k8s://` 的 namespace 仅来自 `-n` flag（[root.go parseSources](file:///Users/vance/project/mineProject/swe/09101503/project-03/cmd/root.go#L1016-L1026)）。glob 在 `reader.expandPaths` 内展开，一个 `FileReader` 持有多路径，`Name()` 聚合成 `"N files"`。
- 行通道：`LogReader.Read` 返回 `<-chan string`（[reader.go#L19-L22](file:///Users/vance/project/mineProject/swe/09101503/project-03/pkg/reader/reader.go#L19-L22)），fan-in（[root.go#L663-L718](file:///Users/vance/project/mineProject/swe/09101503/project-03/cmd/root.go#L663-L718)）、有序并行解析（[pipeline.go](file:///Users/vance/project/mineProject/swe/09101503/project-03/cmd/pipeline.go)）、tail、watch（`chan string` → TUI `LineMsg string`）、guard（`Guard.Run(ctx, <-chan string, ...)`）全部只传裸字符串，fan-in 后来源信息丢失。
- 统计：全局 `types.Stats` / `OperationalStats`（[types.go#L306-L496](file:///Users/vance/project/mineProject/swe/09101503/project-03/pkg/types/types.go#L306-L496)）；解析错误只在 once 模式计数后写入 `Stats.ParseErrors`，follow/interval/top/baseline 不计数；`OperationalStats.ParseErrors` 声明但从未填充。
- 输出：`output.Report` 支持 table/json/csv/html/elasticsearch/opensearch/loki（[output.go](file:///Users/vance/project/mineProject/swe/09101503/project-03/pkg/output/output.go)、[remote.go](file:///Users/vance/project/mineProject/swe/09101503/project-03/pkg/output/remote.go)、[html.go](file:///Users/vance/project/mineProject/swe/09101503/project-03/pkg/output/html.go)）；所有远程格式就是 `reportData()` 的单个 JSON 文档，Loki 固定 `job=caddy-analyzer, source=report` 标签。
- top 子命令维度表（[top.go#L183-L238](file:///Users/vance/project/mineProject/swe/09101503/project-03/cmd/top.go#L183-L238)），无 source 维度。
- 错误策略：once/interval/top 遇源打开失败打印后 `continue`；follow/tail 用 `fanInFollow` 跳过坏源；watch/guard 的 policy 返回错误即终止；文件中途错误由 `printReadError(path)` 指出具体文件。
- 排序确定性：`analysis.TopN` 已按 count 降序、key 升序排序。
- 单源默认行为由大量测试固定（output golden、tui 16 处 `NewModel(make(chan string))`、reader/pipeline/fanin 测试），**来源分区必须只在观测到 >1 个来源时出现**。

## 设计要点

### 1. 规范来源身份（canonical key）

`types.LogSource.Canonical() string`：

- stdin → `stdin`
- file → `filepath.Clean(path)`（`a.log` 与 `./a.log` 合并；glob 按 `filepath.Glob` 的排序结果逐文件生成身份）
- docker → `docker://<container>`
- k8s → `k8s://<namespace>/<pod>`，namespace 为空时规范为 `default`
- journalctl → `journalctl://<unit>`

`reader.ParseSource` 额外支持 `k8s://<ns>/<pod>` 形式（pod 名不含 `/`，无歧义）；`-n` 仍只在 ns 为空时填充（现有逻辑不变）。

新增 `types.SourcedLine{Source, Text string}` 作为所有行通道元素；`LogEntry` 与 `OperationalEntry` 增加 `Source string` 字段（parser 保持纯粹，由管线在 parse 后打标）。

### 2. 来源展开与去重（cmd 层单点）

新增 `planSources([]LogSource) []LogSource`：file 类型先 glob 展开（无匹配保留原 pattern，与现状一致），按 `Canonical()` 去重，其余 scheme 直接按键去重。在 `resolveSources` 的所有返回路径统一应用（args/config/stdin/自动探测）。glob 匹配到的每个文件成为独立逻辑源；重复指定合并到同一统计键。

### 3. 标签随管线端到端传递

- `LogReader.Read` 返回 `<-chan types.SourcedLine`：FileReader 按**具体文件路径**逐行打标（follow 多文件并发路径同样处理）；docker/k8s/journalctl/stdin 打各自规范名；打开/中途错误仍走原有 `printReadError(path)` / onError 回调，策略不变。
- `processParsedLines` 接收 `<-chan types.SourcedLine`，job/result 结构携带 source，并行 parse 后在 reducer 内给 entry 打标（HTTP、operational、parse failure 三者都不丢标签、不串换），回调签名 `func(source string, entry types.Entry, err error)`。
- 各消费方（once/follow/interval/top/baseline/diff/tail/watch）适配新签名。
- guard 不改 `pkg/guard` API：在 `cmd/guard.go` 用一个桥接 goroutine 把 `SourcedLine.Text` 喂给 `Guard.Run(<-chan string)`。

### 4. 按来源统计（保留全部现有全局统计）

- `Stats` 增加 `SourceCounts`、`SourceParseErrors`；`OperationalStats` 增加 `SourceCounts`（均在构造函数初始化）。
- Engine/OperationalEngine 仅对 **非空 Source** 且通过现有过滤后的条目递增（空 Source 不计，保证直接构造 entry 的旧路径无幻影来源）。
- once 模式按来源累计 parse errors；follow/interval 模式也补齐 parse error 计数（目前完全缺失），随窗口重置。
- 新增 `types.SourceStat{Source, Requests, OperationalEvents, ParseErrors}` 与 `analysis.SourceStats(requests, ops, errs)`：三 map 并集（跳过空键），按 `(requests+ops+errors)` 降序、source 升序**统一确定性排序**，所有格式共用。

### 5. 输出一致性（仅多源时出现分区）

报告按统一的 `[]SourceStat` 输出，且**仅当 distinct 来源 >1 时渲染**（单源输出字节不变）：

- table：`Sources Breakdown` 小节（source / requests / operational events / parse errors）；detect 表格也加入简版来源行。
- JSON：`"sources": [...]`（固定字段顺序、有序切片）。
- CSV：`sources:source,requests,operational_events,parse_errors` 小节，单元格走 `SafeCell`。
- HTML：在 `</body>` 前注入 sources 卡片（与 operational 卡片同手法）。
- ES/OpenSearch/Loki：`reportData()` 自带 `sources` 数组，远程文档自动包含，无需改 exporter。
- `top source` 新维度走 `SourceCounts` + `TopN`（count 降序、key 升序，与统一排序同 tie-break），JSON/CSV/table 复用现有渲染。

### 6. tail / watch 多源显示

- tail：`len(plannedSources)>1` 时每行前加暗色 `[source] ` 前缀（HTTP 与 operational 均加）；单源格式完全不变。
- watch：TUI 增加 `multiSource`（`SetMultiSource` setter，构造函数签名不变）；Realtime 视图多源时行首显示截断的来源；Summary 视图多源时显示 Top Sources 列表。`LineMsg` 改为 `{Source, Text string}`，通道改为 `chan types.SourcedLine`。

## Files and Modules

- `pkg/types/types.go`：`Source` 字段、`Canonical()`、`SourcedLine`、`SourceStat`、Stats/OperationalStats 新 map 与初始化。
- `pkg/reader/reader.go`：通道类型改 `SourcedLine` 并逐行打标；k8s `ns/pod` 解析。
- `pkg/analysis/analysis.go`、`pkg/analysis/operational.go`：来源计数、`SourceStats` 聚合排序。
- `pkg/output/output.go`：table/json/csv/detect 多源分区（共用排序）。
- `pkg/output/html.go`：sources 卡片。
- `pkg/tui/dashboard.go`：带来源的 LineMsg/通道、多源展示、Setter。
- `cmd/root.go`：`planSources`、`resolveSources` 接入、fan-in 类型化、once/follow/interval/watch 适配与按来源错误计数。
- `cmd/pipeline.go`：带 source 的有序并行解析。
- `cmd/tail.go`、`cmd/top.go`、`cmd/baseline.go`、`cmd/diff.go`、`cmd/guard.go`：适配；top 增加 source 维度；guard 桥接。
- 测试更新与新增：`pkg/reader/reader_test.go`、`pkg/tui/dashboard_test.go`、`cmd/pipeline_test.go`、`cmd/fanin_test.go`；新增 `pkg/types` canonical 测试、`cmd` 展开去重/标签不串换测试、`pkg/analysis` SourceStats 排序测试、`pkg/output` 多源各格式与单源不变测试、`cmd` top source 测试。

## Implementation Steps

1. types：字段/身份/聚合类型（含 Canonical 单测）。
2. reader：SourcedLine 化 + 逐文件打标 + k8s ns/pod（更新 reader 测试，新增身份断言）。
3. analysis：两个 engine 的来源计数 + `SourceStats`（单测）。
4. cmd/pipeline.go：标签穿透有序并行解析（更新 pipeline_test）。
5. cmd：planSources/resolveSources 去重展开；fan-in 类型化；once/follow/interval 接入（fanin_test 更新 + 新增多源标签、去重测试）。
6. tail/top/baseline/diff/guard 适配；top source 维度。
7. output：table/json/csv/html 多源分区（单测：多源出现、单源缺席、排序与跨格式一致）。
8. tui：通道/消息类型与多源展示（批量更新 dashboard_test）。
9. 全量验证与手工 CLI 冒烟。

## Dependencies and Considerations

- 不新增第三方依赖；不触碰 docs（无需 minify）。
- baseline JSON 仅新增可空 map，旧基线反序列化 nil map 兼容（聚合跳过空键）。
- 来源数量很小，来源计数不受 MaxCardinality 限制，保证可核对（各来源之和等于全局总数，过滤口径一致：均只计过滤后条目）。
- watch 拒绝 stdin、guard 需要 root 等现有前置行为不变。
- `-n` 与 `k8s://ns/pod` 同时出现时：URL 内 ns 优先（flag 仅在为空时填充），与现有"flag 只填空值"语义一致。

## Validation

- `go vet ./...`、`go test ./...`、`go build ./...` 全绿。
- 新增单测覆盖：canonical 各 scheme（含 stdin、无 ns k8s）、glob 逐文件身份、重复源合并、并行解析标签不串换/不丢失（含 parse error 归属）、SourceStats 确定性排序、各输出格式多源一致且单源不变、top source。
- 手工冒烟（testdata 两个文件）：table/json/csv/html 报告含一致 sources；`top source`；多源 `tail`（timeout 包裹）显示前缀、单源无前缀；坏源诊断指出准确来源且好源继续。

## Risks

- TUI/reader 测试面较大（通道类型变更）：逐文件机械更新 + go test 兜底；构造函数保持签名以缩小爆炸半径。
- follow 补齐 parse error 计数属行为微调：仅限存在坏行时，单源干净日志输出不变。
- 报告分区门槛用"观测到 >1 个来源"而非"传入 >1 个参数"：某源完全打不开时无幻影数据，错误仍由 stderr 诊断指出。
