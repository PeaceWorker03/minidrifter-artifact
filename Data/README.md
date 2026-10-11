419mintesapp：该文件夹包含 RQ1 基准评测中 419 个微信小程序样本级检测结果，用于对照 KeyMagnet、TaintMini 与 MiniDrifter 的准确率指标。

FullScaleCorpus：该文件夹包含 RQ2 全量语料评测结果，覆盖 41,362 个微信小程序的程序级统计、威胁实例级记录，以及按品类与威胁类型汇总的结果。

CrossPlatformTransfer：该文件夹包含 RQ4 跨平台迁移评测结果，记录从微信受影响样本到 QQ、支付宝、抖音、百度的匹配关系、人工复验结论，以及适配后 MiniDrifter 的检测结果。

Proof of Concept：该文件夹包含代表性案例的概念验证材料，以及已收到的官方漏洞认证/致谢凭证（CNVD、补天 Butian/QTVA、Vulbox 等编号截图）。

419mintesapp_source.zip：RQ1 所用 419 个小程序源码打包文件（约 1.4GB，超过 git 单文件限制）。请从 Release 下载：https://github.com/PeaceWorker03/minidrifter-artifact/releases/tag/data-sources-v1

脱敏说明：公开数据中的程序编号均为匿名标识（如 `wx00001`、`qq001`），不包含真实小程序名称、原始 appid、后端 URL、鉴权材料及可直接利用的请求内容。各表加总已与论文图表对齐；复现时请自行按 CSV 字段汇总核对。
