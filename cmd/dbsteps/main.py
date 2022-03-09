#!/usr/bin/env python3

"""Imports websteps measurements in a DB-like fashion and allows you
to interactively query them to figure out what is happening."""

import argparse
import json
import shlex
import tabulate
from typing import Any, List, Dict, Optional


class Flag:
    """An analysis flag."""

    def __init__(self, flag, tag):
        self.flag = flag
        self.tag = tag


FLAGS: List[Flag] = [
    Flag(1 << 0, "#gave_up"),
    Flag(1 << 1, "#unexpected"),
    Flag(1 << 2, "#inconclusive"),
    Flag(1 << 3, "#dns_failure"),
    Flag(1 << 4, "#tcp_failure"),
    Flag(1 << 5, "#tls_failure"),
    Flag(1 << 6, "#quic_failure"),
    Flag(1 << 7, "#http_failure"),
    Flag(1 << 8, "#http_diff"),
    Flag(1 << 9, "#dns_diff"),
    Flag(1 << 10, "#accessible"),
    Flag(1 << 11, "#probe_bug"),
    Flag(1 << 24, "#dns_bogon"),
    Flag(1 << 25, "#dns_valid_https"),
    Flag(1 << 26, "#dns_nxdomain"),
    Flag(1 << 27, "#dns_no_answer"),
    Flag(1 << 28, "#dns_refused"),
    Flag(1 << 29, "#timeout"),
    Flag(1 << 30, "#unknown_failure"),
    Flag(1 << 31, "#epnt_valid_https"),
    Flag(1 << 32, "#epnt_via_th"),
    Flag(1 << 33, "#connreset"),
    Flag(1 << 34, "#http_body_diff"),
    Flag(1 << 35, "#http_status_diff"),
    Flag(1 << 36, "#http_header_diff"),
    Flag(1 << 37, "#http_title_diff"),
    Flag(1 << 38, "#ipv6_false_positive"),
]


def jsonl_reader(filepath: str):
    """Reads a JSONL file returning each measurement."""
    with open(filepath, "rb") as filep:
        for line in filep:
            try:
                measurement = json.loads(line)
            except ValueError:
                continue
            else:
                yield measurement


class URLMeasurement:
    """A whole URL measurement."""

    def __init__(self, json: Dict[str, Any]):
        self.id: int = json.get("id", 0)
        self.endpoint_ids: List[int] = json.get("endpoint_ids", [])
        self.url: str = json.get("url", "")
        self.dns: List[int] = []
        self.endpoint: List[int] = []
        self.analysis: List[int] = []


class DNSMeasurement:
    """A DNS measurement."""

    def __init__(self, origin: str, json: Dict[str, Any]):
        self.id: int = json.get("id", 0)
        self.origin: str = origin
        self.url_measurement_id: int = json.get("url_measurement_id", 0)
        self.domain: str = json.get("domain", "")
        self.failure: Optional[str] = json.get("failure", None)
        self.addresses: List[str] = json.get("addresses", [])
        self.alpns: List[str] = json.get("alpns", [])


class EndpointMeasurement:
    """An endpoint measurement."""

    def __init__(self, origin: str, json: Dict[str, Any]):
        self.id: int = json.get("id", 0)
        self.origin: str = origin
        self.url_measurement_id: int = json.get("url_measurement_id", 0)
        self.url: str = json.get("url", "")
        self.endpoint: str = json.get("endpoint", "")
        self.failure: Optional[str] = json.get("failure", None)
        self.failed_operation: Optional[str] = json.get("failed_operation", None)


class AnalysisResult:
    """Result of analyzing DNS or endpoint measurement."""

    def __init__(self, kind: str, json: Dict[str, Any]):
        self.kind: str = kind
        self.id: int = json.get("id", 0)
        self.url_measurement_id: int = json.get("url_measurement_id", 0)
        self.refs = json.get("refs", [])
        self.flags: List[str] = self._map_flags(json.get("flags", 0))

    def _map_flags(self, flags: int) -> List[str]:
        """Maps flags to their names."""
        out = []
        for flag in FLAGS:
            if (flags & flag.flag) != 0:
                out.append(flag.tag)
        return out


class Database:
    """Creates a DB-like view of websteps measurements."""

    def __init__(self):
        self._analysis: Dict[int, AnalysisResult] = {}
        self._dns: Dict[int, DNSMeasurement] = {}
        self._endpoint: Dict[int, EndpointMeasurement] = {}
        self._url_measurements: Dict[int, URLMeasurement] = {}

    def load(self, filepath: str):
        """Loads the database from a JSONL file."""
        for measurement in jsonl_reader(filepath):
            tk = measurement.get("test_keys")
            if not tk:
                continue
            url = tk.get("url")
            steps = tk.get("steps")
            if not url or not steps:
                continue
            self._load_steps(steps)
        self._fixup_url_measurement_refs()

    def _fixup_url_measurement_refs(self):
        """Ensures that URLMeasurements forward refs to the related results."""

        for entry in self._analysis.values():
            umid = entry.url_measurement_id
            if umid in self._url_measurements:
                um = self._url_measurements[umid]
                um.analysis.append(entry.id)

        for entry in self._dns.values():
            umid = entry.url_measurement_id
            if umid in self._url_measurements:
                um = self._url_measurements[umid]
                um.dns.append(entry.id)

        for entry in self._endpoint.values():
            umid = entry.url_measurement_id
            if umid in self._url_measurements:
                um = self._url_measurements[umid]
                um.endpoint.append(entry.id)

    def _load_steps(self, steps: List[Dict[str, Any]]):
        """Loads the steps of a given websteps measurement."""
        for step in steps:
            self._load_step(step)

    def _load_step(self, step: Dict[str, Any]):
        """Loads a single websteps step."""
        self._load_probe_initial(step)
        self._load_th(step)
        self._load_probe_additional(step)
        self._load_analysis(step)

    def _load_probe_initial(self, step: Dict[str, Any]):
        """Loads the probe_initial section."""
        probe_initial = step.get("probe_initial")
        if not probe_initial:
            return
        self._load_dns_and_endpoint("probe", probe_initial)
        self._load_url_measurement(probe_initial)

    def _load_url_measurement(self, record: Dict[str, Any]):
        """Loads the URL measurement."""
        um = URLMeasurement(record)
        if um.id is not None:
            self._url_measurements[um.id] = um

    def _load_dns_and_endpoint(self, origin: str, record: Dict[str, Any]):
        """Loads the dns and endpoint fields of the given record."""
        dns = record.get("dns", [])
        if dns:
            for entry in dns:
                m = DNSMeasurement(origin, entry)
                if not m.id:
                    continue
                self._dns[m.id] = m
        endpoint = record.get("endpoint", [])
        if endpoint:
            self._load_endpoint(origin, endpoint)

    def _load_endpoint(self, origin: str, endpoints: List[Dict[str, Any]]):
        """Helper to load the endpoints from a list of enpoints."""
        for entry in endpoints:
            m = EndpointMeasurement(origin, entry)
            if not m.id:
                continue
            self._endpoint[m.id] = m

    def _load_th(self, step: Dict[str, Dict[str, Any]]):
        """Loads the th section."""
        th = step.get("th")
        if not th:
            return
        self._load_dns_and_endpoint("th", th)

    def _load_probe_additional(self, step: Dict[str, List[Any]]):
        """Loads the probe_additional section."""
        endpoint = step.get("probe_additional", [])
        if endpoint:
            self._load_endpoint("probe_additional", endpoint)

    def _load_analysis(self, step: Dict[str, Dict[str, Any]]):
        """Loads the analysis section."""
        analysis = step.get("analysis")
        if not analysis:
            return
        for key in ("dns", "endpoint"):
            values = analysis.get(key, [])
            if values:
                for entry in values:
                    ar = AnalysisResult(key, entry)
                    if not ar.id:
                        continue
                    self._analysis[ar.id] = ar
        if "url" in analysis:
            ar = AnalysisResult("url", analysis["url"])
            if ar.id:
                self._analysis[ar.id] = ar

    def find_analysis(self, id: int) -> Optional[AnalysisResult]:
        """Returns the analysis with the given ID."""
        if not id in self._analysis:
            return None
        return self._analysis[id]

    def find_for_printing_table(self, id) -> Dict[str, Any]:
        """Finds anything by ID (works because IDs are unique)."""
        if id in self._analysis:
            return self._analysis[id].__dict__.copy()
        if id in self._dns:
            return self._dns[id].__dict__.copy()
        if id in self._endpoint:
            return self._endpoint[id].__dict__.copy()
        if id in self._url_measurements:
            return self._url_measurements[id].__dict__.copy()
        return {}

    @staticmethod
    def _listall(tbl: Any) -> List[Any]:
        """Helper method for creating listings."""
        out = []
        for key in sorted(tbl.keys()):
            out.append(tbl[key].__dict__.copy())
        return out

    def analysis_table(self) -> List[AnalysisResult]:
        """Returns all the entries in the analysis table."""
        return self._listall(self._analysis)

    def dns_table(self) -> List[DNSMeasurement]:
        """Returns all the entries in the DNS table."""
        return self._listall(self._dns)

    def endpoint_table(self) -> List[EndpointMeasurement]:
        """Returns all the entries in the endpoint table."""
        return self._listall(self._endpoint)

    def url_measurement_table(self) -> List[URLMeasurement]:
        """Returns all the entries in the url_measurement table."""
        return self._listall(self._url_measurements)


def command_help():
    """The help command."""
    print("")
    print("Available commmands:")
    print("")
    print("la")
    print("  shortcut for 'list analysis'")
    print("")
    print("ld")
    print("  shortcut for 'list dns'")
    print("")
    print("le")
    print("  shortcut for 'list endpoint'")
    print("")
    print("lu")
    print("  shortcut for 'list url'")
    print("")
    print("list analysis|dns|endpoint|url")
    print("  lists the content of the related table")
    print("")
    print("quit")
    print("  exits this interactive shell")
    print("")
    print("show <id>")
    print("  shows the object with the given ID")
    print("")


def print_table(rows: List[Any]):
    """Prints a given table to the stdout."""
    print(tabulate.tabulate(rows, headers="keys", tablefmt="grid"))


def command_list(db: Database, table: str):
    """The list command."""
    if table == "analysis":
        print_table(db.analysis_table())
    elif table == "dns":
        print_table(db.dns_table())
    elif table == "endpoint":
        print_table(db.endpoint_table())
    elif table == "url":
        print_table(db.url_measurement_table())
    else:
        print("unknown table", table)


def command_show(db: Database, id: int):
    """Shows a data structure."""
    entry = db.find_for_printing_table(id)
    print(tabulate.tabulate([entry], headers="keys", tablefmt="grid"))


def interactive(db: Database):
    """Provides an interactive shell."""
    while True:
        try:
            command = input("dbsteps> ")
        except EOFError:
            break
        if command == "quit":
            break
        if command == "help":
            command_help()
            continue

        v = shlex.split(command)
        if len(v) < 1:
            print("expected a command name, got nothing")
            continue

        command, args = v[0], v[1:]

        if command == "la":
            if len(args) != 0:
                print("expected zero arguments, got", args)
                continue
            command_list(db, "analysis")
            continue

        if command == "ld":
            if len(args) != 0:
                print("expected zero arguments, got", args)
                continue
            command_list(db, "dns")
            continue

        if command == "le":
            if len(args) != 0:
                print("expected zero arguments, got", args)
                continue
            command_list(db, "endpoint")
            continue

        if command == "lu":
            if len(args) != 0:
                print("expected zero arguments, got", args)
                continue
            command_list(db, "url")
            continue

        if command == "list":
            if len(args) != 1:
                print("expected a single argument, got", args)
                continue
            table = args[0]
            command_list(db, table)
            continue

        if command == "show":
            if len(args) != 1:
                print("expected a single argument, got", args)
                continue
            try:
                id = int(args[0])
            except ValueError:
                print("not a number")
                continue
            else:
                command_show(db, id)
            continue

        print("unknown command", command)


def main():
    """main function"""
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument(
        "-f",
        dest="file",
        action="store",
        help="specify JSONL file containing measurements",
        required=True,
    )
    args = parser.parse_args()
    db = Database()
    db.load(args.file)
    interactive(db)


if __name__ == "__main__":
    main()
