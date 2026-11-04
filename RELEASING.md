# 发布流程 (Release SOP)

本文档定义了本项目（基于 MyGo 构建的客户端）的标准发布流程。下次需要发布时，只需对 AI 说：
> **“按照 RELEASING.md 发布 0.x.x”**

AI 将严格遵循以下标准作业程序执行。

---

## 自动化执行步骤 (SOP)

### 1. 准备与验证
1. 确保本地工作区干净，且拉取远程最新代码：
   ```bash
   git pull --rebase origin main
   ```
2. 运行自动化测试，确保无回归问题：
   ```bash
   go test ./internal/...
   ```

### 2. 生成更新日志与更新版本
1. 获取自上一版本以来的所有提交（若为首发则查看全部提交）：
   ```bash
   # 上一版本已打 tag 时：
   git log $(git describe --tags --abbrev=0)..HEAD --oneline
   ```
2. **编写面向最终用户的中文日志**：
   - 在 [`CHANGELOG.md`](CHANGELOG.md) 顶部新增 `## <version>` 小节（不带 `v` 前缀，如 `## 0.1.0`）。
   - 提取新功能、体验优化与 Bug 修复，使用简洁、友好的中文条目（`- ...`）进行描述（此内容将直接展示在客户端的更新弹窗中）。
3. **同步修改版本号**：
   - 修改 [`mygo.json`](mygo.json) 中的 `"version"` 字段为对应的新版本号（如 `"0.1.0"`）。

### 3. 提交与推送
> **注意顺序**：必须先推 `main`，确认成功后再推 tag。避免一起推送时因远程有更新导致 `main` 被拒绝，却把 tag 推了上去触发错误的构建。

1. 提交版本变更文件，**Commit 标题严格使用版本号本身**（不加 `v` 或 `chore` 等前缀）：
   ```bash
   git add mygo.json CHANGELOG.md
   git commit -m "<version>"
   ```
2. 先推送 `main` 分支：
   ```bash
   git push origin main
   ```
3. 打带 `v` 前缀的 Git Tag 并推送到远程：
   ```bash
   git tag "v<version>"
   git push origin "v<version>"
   ```

### 4. 观察 CI 构建
推送 Tag 会触发 GitHub Actions 中的 `.github/workflows/release.yml`，为 macOS、Windows、Linux 编译、签名、打包安装包及更新清单，并上传到 GitHub Draft Release。

通过 GitHub CLI 查看构建状态：
```bash
gh run watch "$(gh run list --workflow release.yml -L1 --json databaseId -q '.[0].databaseId')" --exit-status
```

### 5. 正式发布
所有平台的构建与上传全部成功后，将 Draft 状态去掉并设为最新版本：
```bash
gh release edit "v<version>" --draft=false --latest
```

---

## 异常回滚处理

若在构建过程中发现错误或发布取消：
1. 删除本地及远程 Tag：
   ```bash
   git tag -d "v<version>"
   git push origin :refs/tags/"v<version>"
   ```
2. 删除已创建的 GitHub 草稿 Release：
   ```bash
   gh release delete "v<version>" --yes
   ```
3. 修复问题后重新从步骤 1 开始执行。
