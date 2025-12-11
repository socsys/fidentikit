from math import ceil
from apiflask import APIBlueprint
from apiflask.fields import String
from flask import current_app
from modules.queries import q, match_scan
from config.cache import cache


bp_passkey = APIBlueprint("passkey", __name__, url_prefix="/passkey")


@bp_passkey.get("/")
@bp_passkey.input({
    "scan_id": String(required=False),
    "tag_name": String(required=False)
}, location="query")
@cache.cached(query_string=True)
def passkey_support(query_data):
    db = current_app.config["db"]
    scan_id = query_data.get("scan_id")
    tag_name = query_data.get("tag_name")

    result = {}
    result["domains_all"] = db["landscape_analysis"].count_documents({**match_scan(db, scan_id, tag_name)})
    result["domains_with_passkey"] = db["landscape_analysis"].count_documents({
        **match_scan(db, scan_id, tag_name),
        "landscape_analysis_result.passkey_detection.detected": True
    })
    result["domains_without_passkey"] = db["landscape_analysis"].count_documents({
        **match_scan(db, scan_id, tag_name),
        **q["match_reachable"],
        "$or": [
            {"landscape_analysis_result.passkey_detection.detected": False},
            {"landscape_analysis_result.passkey_detection": {"$exists": False}}
        ]
    })
    result["domains_not_reachable"] = db["landscape_analysis"].count_documents({
        **match_scan(db, scan_id, tag_name),
        **q["match_unreachable"]
    })
    result["domains_with_other_errors"] = db["landscape_analysis"].count_documents({
        **match_scan(db, scan_id, tag_name),
        **q["match_exception"]
    })

    return {"success": True, "error": None, "data": result}


@bp_passkey.get("/detection_methods")
@bp_passkey.input({
    "scan_id": String(required=False),
    "tag_name": String(required=False)
}, location="query")
@cache.cached(query_string=True)
def passkey_by_detection_methods(query_data):
    db = current_app.config["db"]
    scan_id = query_data.get("scan_id")
    tag_name = query_data.get("tag_name")

    result = {
        "domains_detection_methods": {},
        "domains_by_method": {}
    }
    
    pipeline = [
        {"$project": {
            "domain": 1,
            "landscape_analysis_result.passkey_detection.detected": 1,
            "landscape_analysis_result.passkey_detection.detection_methods": 1
        }},
        {"$match": {
            **match_scan(db, scan_id, tag_name),
            "landscape_analysis_result.passkey_detection.detected": True
        }},
        {"$unwind": "$landscape_analysis_result.passkey_detection.detection_methods"}
    ]
    
    for c in db["landscape_analysis"].aggregate(pipeline):
        method = c["landscape_analysis_result"]["passkey_detection"]["detection_methods"]
        domain = c["domain"]
        
        if method not in result["domains_detection_methods"]:
            result["domains_detection_methods"][method] = []
        result["domains_detection_methods"][method].append(domain)
        
        if method not in result["domains_by_method"]:
            result["domains_by_method"][method] = set()
        result["domains_by_method"][method].add(domain)
    
    return {"success": True, "error": None, "data": {
        "domains_detection_methods": {k: len(v) for k, v in result["domains_detection_methods"].items()},
        "domains_by_method": {k: len(v) for k, v in result["domains_by_method"].items()}
    }}


@bp_passkey.get("/rank")
@bp_passkey.input({
    "scan_id": String(required=False),
    "tag_name": String(required=False),
    "list_id": String(load_default="tranco_6Z2X")
}, location="query")
@cache.cached(query_string=True)
def passkey_by_rank(query_data):
    db = current_app.config["db"]
    scan_id = query_data.get("scan_id")
    tag_name = query_data.get("tag_name")
    list_id = query_data["list_id"]

    list_all = db["top_sites_lists"].count_documents({"id": list_id})
    domains_with_passkey = [(c["domain"], c["rank"]) for c in db["landscape_analysis"].aggregate([
        {"$project": {
            "domain": 1,
            "landscape_analysis_result.passkey_detection.detected": 1
        }},
        {"$match": {
            **match_scan(db, scan_id, tag_name),
            "landscape_analysis_result.passkey_detection.detected": True
        }},
        {"$lookup": {
            "from": "top_sites_lists",
            "localField": "domain",
            "foreignField": "domain",
            "as": "top_sites_lists"
        }},
        {"$unwind": {"path": "$top_sites_lists", "preserveNullAndEmptyArrays": False}},
        {"$match": {"top_sites_lists.id": list_id}},
        {"$addFields": {"rank": "$top_sites_lists.rank"}},
        {"$project": {"domain": 1, "rank": 1}}
    ])]

    result = {}
    range_size = int(list_all / 50) if list_all > 0 else 1
    for domain, rank in domains_with_passkey:
        marker = ceil(int(rank) / float(range_size)) * range_size
        key = f"{marker-range_size}"
        if key not in result:
            result[key] = []
        result[key].append(domain)

    return {"success": True, "error": None, "data": {
        "domains_with_passkey_by_rank": {k: len(set(v)) for k, v in result.items()}
    }}


@bp_passkey.get("/confidence")
@bp_passkey.input({
    "scan_id": String(required=False),
    "tag_name": String(required=False)
}, location="query")
@cache.cached(query_string=True)
def passkey_by_confidence(query_data):
    db = current_app.config["db"]
    scan_id = query_data.get("scan_id")
    tag_name = query_data.get("tag_name")

    result = {}
    pipeline = [
        {"$project": {
            "domain": 1,
            "landscape_analysis_result.passkey_detection.detected": 1,
            "landscape_analysis_result.passkey_detection.confidence": 1
        }},
        {"$match": {
            **match_scan(db, scan_id, tag_name),
            "landscape_analysis_result.passkey_detection.detected": True
        }}
    ]
    
    for c in db["landscape_analysis"].aggregate(pipeline):
        confidence = c["landscape_analysis_result"]["passkey_detection"].get("confidence", "NONE")
        domain = c["domain"]
        
        if confidence not in result:
            result[confidence] = []
        result[confidence].append(domain)
    
    return {"success": True, "error": None, "data": {
        "domains_by_confidence": {k: len(set(v)) for k, v in result.items()}
    }}


@bp_passkey.get("/webauthn_api")
@bp_passkey.input({
    "scan_id": String(required=False),
    "tag_name": String(required=False)
}, location="query")
@cache.cached(query_string=True)
def passkey_by_webauthn_api(query_data):
    db = current_app.config["db"]
    scan_id = query_data.get("scan_id")
    tag_name = query_data.get("tag_name")

    result = {
        "domains_with_api": 0,
        "domains_without_api": 0,
        "domains_with_api_and_passkey": 0,
        "domains_without_api_but_passkey": 0
    }
    
    pipeline = [
        {"$project": {
            "domain": 1,
            "landscape_analysis_result.passkey_detection.detected": 1,
            "landscape_analysis_result.passkey_detection.webauthn_api_available": 1
        }},
        {"$match": {
            **match_scan(db, scan_id, tag_name),
            **q["match_reachable"]
        }}
    ]
    
    for c in db["landscape_analysis"].aggregate(pipeline):
        passkey_detection = c["landscape_analysis_result"].get("passkey_detection", {})
        detected = passkey_detection.get("detected", False)
        api_available = passkey_detection.get("webauthn_api_available", False)
        
        if api_available:
            result["domains_with_api"] += 1
            if detected:
                result["domains_with_api_and_passkey"] += 1
        else:
            result["domains_without_api"] += 1
            if detected:
                result["domains_without_api_but_passkey"] += 1
    
    return {"success": True, "error": None, "data": result}


