# Excel to Database Importer

这个Python脚本可以读取Excel文件并将数据导入到数据库中。

## 功能特性

- 读取外部Excel文件（支持多个工作表）
- 支持多种数据库（MySQL、SQLite等）
- 简单易用的配置方式
- 错误处理和日志输出

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 1. 准备Excel文件

确保你有一个格式正确的Excel文件。第一行应该是列标题。

### 2. 配置数据库连接

在 [excel_to_db.py](file:///D:/gz/excel_to_db.py) 文件中修改数据库配置:

```python
# 数据库配置
db_config = {
    'host': 'localhost',
    'port': 3306,
    'username': 'your_username',
    'password': 'your_password',
    'database': 'your_database',
    'db_type': 'mysql'  # 或者 'sqlite'
}
```

### 3. 修改文件路径和表名

```python
# 配置参数
excel_file = "C:/path/to/your/excel_file.xlsx"  # Excel文件路径
sheet_name = 0                       # 工作表名称或索引
table_name = "your_table_name"       # 数据库表名
```

### 4. 运行脚本

```bash
python excel_to_db.py
```

或者通过命令行参数指定Excel文件路径：
```bash
python excel_to_db.py /path/to/your/excel_file.xlsx
```

## 自定义使用

你可以导入这些函数并在自己的代码中使用:

```python
from excel_to_db.excel_to_db import read_excel_data, create_db_connection, insert_data_to_db

# 读取数据
df = read_excel_data('C:/path/to/data.xlsx')

# 创建数据库连接
engine = create_db_connection('localhost', 3306, 'user', 'pass', 'dbname')

# 插入数据
insert_data_to_db(df, 'table_name', engine)
```

## 注意事项

1. 确保数据库服务器正在运行
2. 确保数据库用户有足够的权限
3. 如果目标表不存在，程序会自动创建
4. 如果目标表已存在，默认会在表中追加数据
5. Excel文件不需要包含在项目目录中，可以从任何可访问的路径读取