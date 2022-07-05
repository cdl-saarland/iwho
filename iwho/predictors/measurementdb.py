""" Interface to store prediction results in an sqlite3 database.
"""


from datetime import datetime
import sqlite3
import os

from ..configurable import ConfigMeta

class MeasurementDB(metaclass=ConfigMeta):
    """ Handler class for an sqlite3 database to log the encountered prediction
    results of throughput predictors.

    Normal use will create one instance of this class (per database, of which
    typically only one should be needed) and use it in a `with` statement as a
    context manager whenever a database operation is performed.
    """

    config_options = dict(
        db_path = ('measurement.db',
            'path and file name of the sqlite3 database to use'),
    )

    def __init__(self, config):
        self.configure(config)

        self.con = None
        self.nesting_level = 0 # for making the ContextManager re-entrant

        if not os.path.isfile(self.db_path):
            self._init_con()
            self.create_tables()
            self._deinit_con()

    def _init_con(self):
        self.con = sqlite3.connect(self.db_path)
        self.con.row_factory = sqlite3.Row

    def _deinit_con(self):
        self.con.close()
        self.con = None

    def __enter__(self):
        if self.nesting_level == 0:
            self._init_con()
        self.nesting_level += 1
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.nesting_level -= 1
        if self.nesting_level == 0:
            self._deinit_con()

    def get_series(self, series_id):
        """ Obtain the series matching the `series_id` from the database.
        The result is a structure of lists and dictionaries representing a
        sequence of basic block throughput estimations.
        """
        con = self.con
        assert con is not None
        cur = con.cursor()

        series_dict = dict(series_id=series_id)

        cur.execute("SELECT source_computer, timestamp FROM series WHERE series_id=?", (series_id,))
        result = cur.fetchone()

        if result is None:
            return None

        series_dict["series_date"] = datetime.fromtimestamp(result["timestamp"]).isoformat()
        series_dict["source_computer"] = result["source_computer"]

        cur.execute("""
                SELECT mmnts.measurement_id, input, predictor, result, remark
                FROM (SELECT * FROM measurements WHERE series_id=?) AS mmnts
                INNER JOIN predictor_runs ON mmnts.measurement_id = predictor_runs.measurement_id""",
            (series_id,))

        meas_dicts = dict()

        for r in cur.fetchall():
            pred_run = dict()
            pred_run["result"] = r["result"]
            pred_run["remark"] = r["remark"]
            pred_run["predictor"] = r["predictor"]
            meas_id = r['measurement_id']
            md = meas_dicts.get(meas_id, None)
            if md is None:
                md = dict()
                md['measurement_id'] = meas_id
                md['input'] = r['input']
                md["predictor_runs"] = []
                meas_dicts[meas_id] = md
            md["predictor_runs"].append(pred_run)

        series_dict["measurements"] = [v for k, v in meas_dicts.items()]
        return series_dict

    def create_tables(self):
        """ Set up the database tables.
        """
        con = self.con
        assert con is not None

        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS series (
                series_id INTEGER NOT NULL PRIMARY KEY,
                source_computer TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )""")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS measurements (
                measurement_id INTEGER NOT NULL PRIMARY KEY,
                series_id INTEGER NOT NULL,
                input TEXT NOT NULL
            )""")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS predictor_runs (
                predrun_id INTEGER NOT NULL PRIMARY KEY,
                measurement_id INTEGER NOT NULL,
                predictor TEXT NOT NULL,
                result REAL,
                remark TEXT
            )""")

        # create an index to dramatically speed up `get_series()` queries
        cur.execute("""
            CREATE INDEX IF NOT EXISTS predictor_runs_idx ON
                predictor_runs(measurement_id)
            """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS discoveries (
                discovery_id INTEGER NOT NULL PRIMARY KEY,
                remark TEXT
            )""")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS witnesses (
                discovery_id INTEGER NOT NULL,
                measurement_id INTEGER NOT NULL,
                PRIMARY KEY (discovery_id, measurement_id)
            )""")
        con.commit()


    def add_series(self, measdict):
        """ Insert a measurement series into the database.
        `measdict` needs to be a dictionary with the following structure:
            {
              "series_date": $date,
              "source_computer": "$name",
              "measurements": [{
                  "input": "49ffabcdef",
                  "predictor_runs": [{
                      "predictor": "llvm-mca.12-r+a.skl",
                      "result": 42.17,
                      "remark": null
                  }]
              }]
            }
        """

        con = self.con
        assert con is not None

        series_date = measdict["series_date"]
        timestamp = round(datetime.fromisoformat(series_date).timestamp())

        source_computer = measdict["source_computer"]

        cur = con.cursor()

        # add a new series
        cur.execute("INSERT INTO series VALUES (NULL, ?, ?)", (source_computer, timestamp))
        series_id = cur.lastrowid

        for m in measdict["measurements"]:
            inp = m["input"]

            cur.execute("INSERT INTO measurements VALUES (NULL, ?, ?)", (series_id, inp))
            measurement_id = cur.lastrowid

            predictor_runs = m["predictor_runs"]

            for r in predictor_runs:
                predictor = r["predictor"]
                res = r.get("result", None)
                remark = r.get("remark", None)
                cur.execute("INSERT INTO predictor_runs VALUES (NULL, ?, ?, ?, ?)", (measurement_id, predictor, res, remark))

        con.commit()

        return series_id

