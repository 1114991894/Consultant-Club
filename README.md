# Consultant Club — 官方网站

AI 与咨询融合落地的咨询公司平台官网，侧重 **AI 咨询** 与 **咨询项目** 展示。

🔗 **在线访问**：https://1114991894.github.io/Consultant-Club/

---

## 项目结构

```
.
├── index.html                          # 官网主文件（单文件站，HTML+CSS+JS 全内置）
├── profile-print.html                  # 公司简介 PDF 的印刷版源文件（A4 版式）
├── Consultant Club 公司简介.pdf         # 11 页 A4 公司简介（可直接发客户）
├── assets/                             # 团队成员头像
│   ├── team-yang.jpg                   # 杨景宇 · 战略顾问
│   ├── team-liu.jpg                    # 刘诠案 · AI技术咨询顾问
│   ├── team-doris.jpg                  # Doris · 业绩增长教练
│   └── team-li.jpg                     # 李文科 · 组织发展顾问
└── .nojekyll                           # 关闭 Jekyll 处理，保证资源原样发布
```

## 官网板块

| 板块 | 内容 |
| --- | --- |
| Hero | 品牌主张「让每一家中小企业，进入高速成长状态」+ 关键数据 |
| 关于我们 | 使命与信念 + 三位一体路径（战略咨询 × 智能体定制 × 对赌落地陪跑） |
| 项目咨询师 | 4 位顾问及专业背书 |
| 咨询师价值 | 平台为咨询师提供的六项价值 + 申请入口 |
| 服务体系 | 组织诊断与增长分析 / 战略重构设计 / 运营效率优化 / 专项问题解决方案 |
| AI 咨询 | AI 策略模拟 · 业务智能体定制 · 人才训练系统 · AI 应用落地陪跑 |
| 咨询项目 | 17 个代表案例，支持按战略规划 / 绩效体系 / 组织变革 / 人才发展 / 业绩增长 / 专项培训 筛选 |
| 管理诊断 | 三类最需要诊断的企业 + 诊断的三大价值 |
| 商务合作 | 合作方式、零风险承诺与联系方式 |

## 特性

- 纯静态单文件站，无构建步骤、无外部依赖（仅字体走 CDN）
- 响应式布局，适配移动端
- 滚动侦测导航、入场动效、案例筛选、数字滚动
- 支持 `prefers-reduced-motion` 无障碍降级

## 重新生成 PDF

修改 `profile-print.html` 后，用 Edge/Chrome 无头模式打印为 A4 PDF：

```bash
msedge --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="Consultant Club 公司简介.pdf" \
  --virtual-time-budget=15000 profile-print.html
```

## 本地预览

直接用浏览器打开 `index.html` 即可。

---

© 2026 Consultant Club · 深入一线 · 管理进化 · 陪伴成长 · 驱动增长
