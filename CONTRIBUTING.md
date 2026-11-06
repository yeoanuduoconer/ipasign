# 参与开发

## 环境

- Python 3.10+
- 不需要 Xcode、macOS、编译器
- 只有跑真机安装测试时才需要 Apple 移动设备驱动（Windows）

```bash
git clone <repo>
cd ipasign
python -m pip install -e ".[dev]"
```

可编辑安装（`-e`）后，改动源码立刻生效，无需重新安装。

## 常用命令

```bash
python -m pytest -q              # 全部测试
python -m pytest tests/test_macho.py -q
python -m ipasign selfcheck      # 依赖 / 路径 / 设备自检
python -m ipasign                # 交互界面
```

## 代码结构

```
ipasign/
├── app.py        入口：无参数进 TUI，有参数走 CLI
├── tui.py        交互界面（rich）
├── cli.py        命令行
├── paths.py      所有路径解析（禁止硬编码绝对路径）
├── device.py     装机（pymobiledevice3）
├── watch.py      自动续签任务
├── core/         签名引擎，不依赖 Apple 服务
└── apple/        登录、证书申请、ADI
```

两条约定：

1. **core 层不 import apple 层**，签名引擎应能独立使用
2. **任何路径都走 `paths.py`**，不要出现 `C:\Users\...` 之类写死的路径

## 提交前

```bash
python -m pytest -q
```

CI 会在 Python 3.10 / 3.11 / 3.12 上跑同样的测试，并检查 wheel 里是否包含内置原生库。

## 修改签名逻辑时

`core/macho.py` 里每一处偏移都对应 iOS 的校验规则。如果改动涉及：

- CodeDirectory 版本 / 标志位
- 特殊槽位（Info.plist、Requirements、CodeResources、Entitlements、DER）
- CMS 的 hash agility 属性（`1.2.840.113635.100.9.1` / `.9.2`）

请先看 `docs/ARCHITECTURE.md` 的对应章节，并在测试里补一个回归用例
（`tests/test_macho.py`、`tests/test_cms.py`）。

## 文档

- `README.md`：面向使用者
- `docs/ARCHITECTURE.md`：面向开发者，含踩坑记录
- `SECURITY.md`：数据边界与漏洞报告
