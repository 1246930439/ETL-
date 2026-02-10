# 使用Postman调用数据插入接口指南

本文档详细介绍如何使用Postman通过API Token认证方式调用数据插入接口。

## 准备工作

1. 确保调度工具平台正在运行
2. 获取有效的API Token（例如：3TrEHpjtwcMGkCNVocj2w4ODNQquHyR_4-8kuXoAtNo）
3. 下载并安装Postman工具

## 步骤详解

### 1. 打开Postman并创建新请求

打开Postman应用程序，点击左上角的"New"按钮，选择"Request"：

![创建新请求](images/postman_step1.png)

给请求起个名字，比如"Insert Data to Database"，并选择或创建一个集合来保存这个请求。

### 2. 配置请求基本信息

在请求界面中，设置请求方法为 `POST`，并在URL栏中输入接口地址：

```
http://localhost:5000/api/database/insert
```

![配置请求方法和URL](images/postman_step2.png)

> 注意：如果您将应用部署在其他地址，请相应调整URL。

### 3. 配置Headers（头部信息）

切换到Headers选项卡，添加以下两个键值对：

| Key           | Value                                     |
|---------------|-------------------------------------------|
| Authorization | Bearer 3TrEHpjtwcMGkCNVocj2w4ODNQquHyR_4-8kuXoAtNo |
| Content-Type  | application/json                          |

![配置Headers](images/postman_step3.png)

> 注意：Authorization的值格式是 `Bearer` + 空格 + 您的Token码。

### 4. 配置请求Body（请求体）

切换到Body选项卡：

1. 选择 `raw` 单选按钮
2. 在右侧下拉菜单中选择 `JSON`
3. 在文本框中输入JSON格式的数据：

```json
{
  "table_name": "your_table_name",
  "db_config_id": 1,
  "records": [
    {
      "column1": "value1",
      "column2": "value2",
      "column3": "value3"
    },
    {
      "column1": "value4",
      "column2": "value5",
      "column3": "value6"
    }
  ]
}
```

![配置请求Body](images/postman_step4.png)

请根据实际情况替换以下内容：
- `your_table_name`：替换为目标数据库表名
- `db_config_id`：替换为实际的数据库配置ID（可以在数据库配置页面查看）
- `column1, column2, column3`：替换为目标表的实际列名
- `value1, value2...`：替换为要插入的实际值

### 5. 发送请求

确认所有配置无误后，点击右上角的"Send"按钮发送请求：

![发送请求](images/postman_step5.png)

### 6. 查看响应结果

请求发送后，您将在下方看到响应结果：

成功的响应示例：
```json
{
  "message": "成功插入 2 条记录到表 your_table_name",
  "result": {
    "affected_rows": 2
  }
}
```

失败的响应示例：
```json
{
  "error": "错误描述"
}
```

![查看响应结果](images/postman_step6.png)

## 注意事项

1. 确保调度工具平台正在运行（通过命令 `python web_scheduler.py` 启动）
2. 确保提供的Token是有效的且未过期
3. 确保数据库配置ID是存在的
4. 确保目标表存在且列名正确
5. 如果遇到网络连接问题，请检查服务器地址和端口是否正确

## 故障排除

如果遇到问题，请检查以下几点：

1. **认证失败**：检查Token是否正确，确保前面加上了"Bearer "
2. **连接失败**：检查服务器是否正在运行，URL是否正确
3. **数据格式错误**：检查JSON格式是否正确，字段名是否匹配
4. **数据库配置错误**：检查db_config_id是否存在，数据库是否可连接

通过以上步骤，您就可以成功使用Postman调用数据插入接口了。