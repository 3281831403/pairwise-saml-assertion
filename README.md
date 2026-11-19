# pairwise-saml-assertion

## 题面

单点登录一接入政企客户的身份提供方就出问题：签名引用能指向包装节点，验签通过但业务读到的是另一个断言；注释与 DTD 实体参与规范化，同语义 XML 出现两种签名结果、实体还能把内存撑爆；时间窗只看 NotOnOrAfter、时钟偏移没处理；受众根本不校验；断言可重放。saml_gateway/assertion.py 是核心，tests/test_saml_assertion.py 15个红。要修的是：签名引用必须绑定被验断言；规范化前剥离注释并拒绝 DTD 与超限输入；NotBefore 与 NotOnOrAfter 带 skew 严格判定；受众精确匹配；断言 id 一次性消费。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态下 15 个测试全部失败，汇总行必须是 `15 failed`；不得出现 collection error、import error 或 syntax error。

预期输出：

```text
15 failed
```

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 其他 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 约束

`tests/` 目录不可修改：`tests/test_saml_assertion.py` 是验收标准，不得增删或改写测试；实现只改 `saml_gateway/assertion.py`，并保持其中五个函数的签名、契约与 `InvalidAssertion` 异常类型不变。
