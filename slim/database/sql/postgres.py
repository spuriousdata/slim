import psycopg2


class PostgresDriver(object):
    def __init__(self, c):
        dsn = self.makedsn(c)
        self.connection = psycopg2.connect(dsn)

    def makedsn(self, c):
        return "host={host} user={user} dbname={dbname} port={port}".format(**c._asdict())

    def query(self, q):
        return self.get_cursor().execute(q)

    def get_cursor(self):
        return self.connection.cursor()
