#!/usr/bin/env pytest

import pytest

import os
import sys

import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)

from iwho.predictors.measurementdb import MeasurementDB


def test_mdb_create(tmp_path):
    db_path = tmp_path / 'test.db'
    mdb = MeasurementDB(config={'db_path': db_path})

def test_mdb_get_empty(tmp_path):
    db_path = tmp_path / 'test.db'
    mdb = MeasurementDB(config={'db_path': db_path})

    with mdb:
        res = mdb.get_series(42)

    assert res is None

test_series = {
        "series_date": "2022-03-15T11:43:15",
        "source_computer": "testing",
        "measurements": [
            {
                "input": "49ffabcdef",
                "predictor_runs": [
                    { "predictor": "foo", "result": 42.0, "remark": None },
                    { "predictor": "bar", "result": 17.3, "remark": None },
                ]
            },
            {
                "input": "48ffabcdef",
                "predictor_runs": [
                    { "predictor": "foo", "result": 42.0, "remark": None },
                    { "predictor": "bar", "result": -1, "remark": "error!" },
                ]
            }
        ]
    }

def test_mdb_insert(tmp_path):
    db_path = tmp_path / 'test.db'
    mdb = MeasurementDB(config={'db_path': db_path})

    with mdb:
        sid = mdb.add_series(test_series)

def setify_lists(d):
    if isinstance(d, list) or isinstance(d, tuple):
        return frozenset({setify_lists(e) for e in d})

    if isinstance(d, dict):
        return frozenset({ (k, setify_lists(v)) for k, v in d.items() if not k.endswith("_id")})

    return d


def test_mdb_insert_get(tmp_path):
    db_path = tmp_path / 'test.db'
    mdb = MeasurementDB(config={'db_path': db_path})

    with mdb:
        sid = mdb.add_series(test_series)

        res = mdb.get_series(sid)

    assert res is not None
    assert res['source_computer'] == 'testing'

    meas_ref = setify_lists(test_series)
    meas_res = setify_lists(res)

    assert meas_res == meas_ref

def test_mdb_insert_get_reopen(tmp_path):
    db_path = tmp_path / 'test.db'
    mdb = MeasurementDB(config={'db_path': db_path})

    with mdb:
        sid = mdb.add_series(test_series)

    with mdb:
        res = mdb.get_series(sid)

    assert res is not None
    assert res['source_computer'] == 'testing'

    meas_ref = setify_lists(test_series)
    meas_res = setify_lists(res)

    assert meas_res == meas_ref

def test_mdb_insert_get_multiple(tmp_path):
    db_path = tmp_path / 'test.db'
    mdb = MeasurementDB(config={'db_path': db_path})

    with mdb:
        sid = mdb.add_series(test_series)
        sid2 = mdb.add_series(test_series)

        res = mdb.get_series(sid)

    assert res is not None
    assert res['source_computer'] == 'testing'

    meas_ref = setify_lists(test_series)
    meas_res = setify_lists(res)

    assert meas_res == meas_ref

