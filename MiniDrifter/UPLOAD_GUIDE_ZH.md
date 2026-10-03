# 上传与填充说明

这是目录和文件格式模板，未包含你的真实工具、数据、实验结果或漏洞证明。

1. 解压压缩包。把真实材料放入对应目录；保留工具原来的源码结构和入口，避免仅为目录美观移动代码导致导入失败。
2. CSV 为 UTF-8、英文表头、每行一个记录，当前只有表头，不是论文结果。不要把表头模板当作真实数据提交。Windows Excel 打开时可通过“从文本/CSV”选择 UTF-8。
3. JSON 使用 UTF-8；证据样例带 template_only=true，仅为格式示意。填写后删除该标记，不能把占位内容当实验证据。
4. 将 *_TEMPLATE.md 完整填写并去掉文件名中的 _TEMPLATE；不提供的材料删除模板并在 README 中解释范围。
5. GitHub 首页 Add file → Upload files，拖入本目录中的 README 和五个大类文件夹，保持目录结构；不要仅上传 ZIP，也不要多套一层本模板的外层目录。根目录 .gitignore 可用创建文件方式添加。
6. 更新 README 的 Status、Reproduction 和 Availability，使其与实际内容一致。匿名审稿前检查作者、单位、邮箱、绝对路径、文件元数据与链接。

# 大类与格式
- tool：源代码保持原扩展名（.py/.js/.ts 等），配置 .yaml/.json，依赖采用项目真实的 requirements.txt、environment.yml 或 package.json。不要凭空填写依赖。
- data：清单与标签 .csv，大规模结构化记录 .jsonl，字段定义见 data/README.md。
- results：指标 .csv，图 .pdf（矢量）或 .png，绘图脚本保留实际语言扩展名。
- vulnerability-evidence：报告 .md，脱敏证据 .json，截图 .png/.jpg，脱敏确认函 .pdf，视频可用 .mp4。证据不够时标明未验证，不补写不存在的轨迹。
- docs：说明文档 .md。

# 证据命名
使用 CASE_001、CASE_002 等稳定匿名编号；同一案例在标签、结果和证据索引中保持一致。名称示例：CASE_001_report.md、CASE_001_step_01.png、CASE_001_acknowledgment.pdf。
不得公开真实 token、cookie、密钥、身份证/驾驶证、用户资料或未修复漏洞的可直接利用细节。保留公开证据的意义：固定身份、引用传播、授权判断和敏感效果；将私人原始证据留在仓库外。

# 指标口径
TP/FP/FN 为威胁级计数，应用级指标单独保存。跨平台的 matched、affected 和 threat_count 区分；confirmed 表示哪种确认必须在文档写明。披露状态、严重性、日期按真实凭证填写，不填猜测值。缺失数值留空，并说明缺失原因；不能当作零。
