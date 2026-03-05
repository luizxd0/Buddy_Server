import mysql.connector

conn = mysql.connector.connect(
    host='127.0.0.1',
    user='gbth',
    password='gbthclassic200591',
    database='gbth'
)

cursor = conn.cursor(dictionary=True)

# Check if users exist
test_users = ['test', 'test1', 'kyll3r', 'br']
for user in test_users:
    query = """
        SELECT u.Id, u.UserId, g.NickName 
        FROM user u 
        LEFT JOIN game g ON u.UserId = g.UserId 
        WHERE u.UserId = %s OR g.NickName = %s
    """
    cursor.execute(query, (user, user))
    result = cursor.fetchone()
    if result:
        print(f"[OK] User '{user}' found: Id={result['Id']}, UserId={result['UserId']}, NickName={result['NickName']}")
    else:
        print(f"[FAIL] User '{user}' NOT FOUND")

cursor.close()
conn.close()
