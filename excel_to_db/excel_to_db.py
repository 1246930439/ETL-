import pandas as pd
from sqlalchemy import create_engine, text
import os
import argparse
import logging
import sys

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler("excel_to_db.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def read_excel_data(file_path, sheet_name=0):
    """
    读取Excel文件中的数据
    
    Args:
        file_path (str): Excel文件路径
        sheet_name (int/str): 工作表名称或索引，默认为第一个工作表
    
    Returns:
        DataFrame: 包含Excel数据的DataFrame
    """
    logger.info(f"Reading Excel data from: {file_path}")
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"找不到文件: {file_path}")
    
    # 读取Excel文件
    df = pd.read_excel(file_path, sheet_name=sheet_name)
    logger.info(f"Successfully read {len(df)} rows from Excel file")
    print(f"成功读取 {len(df)} 行数据")
    return df

def create_db_connection(host, port, username, password, database, db_type='mysql'):
    """
    创建数据库连接
    
    Args:
        host (str): 数据库主机地址
        port (int): 数据库端口
        username (str): 用户名
        password (str): 密码
        database (str): 数据库名
        db_type (str): 数据库类型，默认为mysql
    
    Returns:
        engine: SQLAlchemy引擎对象
    """
    logger.info(f"Creating database connection to {db_type} database: {database}")
    if db_type == 'mysql':
        # MySQL连接字符串
        connection_string = f'mysql+pymysql://{username}:{password}@{host}:{port}/{database}'
    elif db_type == 'sqlite':
        # SQLite连接字符串
        connection_string = f'sqlite:///{database}'
    else:
        logger.error(f"Unsupported database type: {db_type}")
        raise ValueError(f"不支持的数据库类型: {db_type}")
    
    # 创建数据库引擎
    engine = create_engine(connection_string)
    logger.info("Database connection created successfully")
    return engine

def insert_data_to_db(dataframe, table_name, engine, if_exists='append'):
    """
    将数据插入到数据库
    
    Args:
        dataframe (DataFrame): 要插入的数据
        table_name (str): 数据库表名
        engine: SQLAlchemy引擎
        if_exists (str): 如果表存在如何处理 ('fail', 'replace', 'append')
    
    Returns:
        None
    """
    logger.info(f"Inserting data into table: {table_name}")
    try:
        # 如果是append模式，先清空表数据再插入新数据
        if if_exists == 'append':
            with engine.begin() as conn:
                conn.execute(text(f"DELETE FROM {table_name}"))
            logger.info(f"Cleared all data from table {table_name}")
        print(f"已清空表 {table_name} 中的所有数据")
        
        # 插入数据到数据库
        dataframe.to_sql(table_name, engine, if_exists=if_exists, index=False)
        logger.info(f"Successfully inserted {len(dataframe)} rows into table {table_name}")
        print(f"成功插入 {len(dataframe)} 行数据到表 {table_name}")
    except Exception as e:
        logger.error(f"Error inserting data: {e}")
        print(f"插入数据时出错: {e}")

def main(excel_file=None):
    """
    主函数 - 演示如何使用上述函数
    
    Args:
        excel_file (str): 可选的Excel文件路径，如果不提供则使用默认值
    """
    logger.info("Starting Excel to DB import process")
    # 配置参数
    excel_file = excel_file or "C:\\Users\\Lenovo\\Desktop\\独立站数据.xlsx"  # Excel文件路径
    sheet_name = 0                   # 工作表名称或索引
    table_name = "dwd_sale_shopify_order_di"        # 数据库表名
    
    # 数据库配置
    db_config = {
        'host': 'localhost',
        'port': 3306,
        'username': 'root',
        'password': '123456',
        'database': 'erp_system',
        'db_type': 'mysql'  # 或者 'sqlite'
    }
    
    try:
        # 步骤1: 读取Excel数据
        logger.info("Step 1: Reading Excel data")
        print("正在读取Excel数据...")
        df = read_excel_data(excel_file, sheet_name)
        print("前5行数据预览:")
        print(df.head())
        logger.info("First 5 rows of data preview completed")
        
        # 步骤2: 创建数据库连接
        logger.info("Step 2: Creating database connection")
        print("\n正在创建数据库连接...")
        engine = create_db_connection(**db_config)
        
        # 步骤3: 插入数据到数据库
        logger.info("Step 3: Inserting data to database")
        print("\n正在插入数据到数据库...")
        insert_data_to_db(df, table_name, engine)
        
        logger.info("Excel to DB import process completed successfully")
        print("\n操作完成!")
        
    except Exception as e:
        logger.exception(f"Error during Excel to DB import process: {e}")
        print(f"程序执行出错: {e}")

# 示例用法
if __name__ == "__main__":
    logger.info("Excel to DB script started from command line")
    parser = argparse.ArgumentParser(description='将Excel数据导入数据库')
    parser.add_argument('excel_file', nargs='?', help='Excel文件路径')
    args = parser.parse_args()
    
    main(args.excel_file)
    logger.info("Excel to DB script completed")