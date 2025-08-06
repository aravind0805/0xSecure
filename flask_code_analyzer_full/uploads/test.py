# test.py (vulnerable code)
import sqlite3

password = "123456"  # hardcoded password

name = input("Enter your name:")
query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)

eval("print('hello')")
