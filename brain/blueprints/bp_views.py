from apiflask import APIBlueprint
from flask import render_template, send_from_directory, current_app


bp_views = APIBlueprint("views", __name__, url_prefix="/", enable_openapi=False)


@bp_views.get("/")
def index():
    return render_template("views/index.html")


@bp_views.get("/archive")
def sso_archive():
    db = current_app.config["db"]
    return render_template("views/archive.html",
        lists=db["top_sites_lists"].distinct("id"),
        gts=db["ground_truth"].distinct("gt_id"),
        idps=sorted(list(set(db["ground_truth"].find({"idp_name": {"$ne": None}}).distinct("idp_name")))),
        queries=list(db["queries"].find({}, {"_id": False}))
    )


@bp_views.get("/stats")
def sso_stats():
    return render_template("views/stats.html")


@bp_views.get("/diff")
def sso_diff():
    return render_template("views/diff.html")


@bp_views.get("/list")
def sso_list():
    return render_template("views/list.html")


@bp_views.get("/admin")
def admin():
    db = current_app.config["db"]
    
    # Get authentication stats with error handling
    try:
        # Get landscape passkey detection count (using new passkey_detection structure)
        passkey_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.passkey_detection.detected": True
        })
        
        # Get passkey UI count based on detection_methods containing UI_ELEMENT
        passkey_ui_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.passkey_detection.detected": True,
            "landscape_analysis_result.passkey_detection.detection_methods": "UI_ELEMENT"
        })
        
        # Get passkey JS detection count
        passkey_js_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.passkey_detection.detected": True,
            "landscape_analysis_result.passkey_detection.detection_methods": "JS_API"
        })
        
        # Keep MFA count
        mfa_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.authentication_mechanisms.mfa": {"$not": {"$size": 0}}
        })
        
        # Get password-based auth count
        password_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.authentication_mechanisms.password": {"$not": {"$size": 0}}
        })
        
        # Get WebAuthn parameter analysis count (passkey worker)
        passkey_analyzed_count = db["passkey_analysis"].count_documents({})
        passkey_detected_count = db["passkey_analysis"].count_documents({
            "passkey_analysis_result.passkey.detected": True
        })
        
        # Get identity provider counts
        google_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.identity_providers.idp_name": "GOOGLE"
        })
        
        microsoft_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.identity_providers.idp_name": "MICROSOFT"
        })
        
        apple_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.identity_providers.idp_name": "APPLE"
        })
        
        github_count = db["landscape_analysis"].count_documents({
            "landscape_analysis_result.identity_providers.idp_name": "GITHUB"
        })
        
        # Total identity provider count
        idp_total_count = google_count + microsoft_count + apple_count + github_count
    except Exception as e:
        current_app.logger.error(f"Error fetching authentication stats: {e}")
        passkey_count = 0
        passkey_ui_count = 0
        passkey_js_count = 0
        mfa_count = 0
        password_count = 0
        passkey_analyzed_count = 0
        passkey_detected_count = 0
        google_count = 0
        microsoft_count = 0
        apple_count = 0
        github_count = 0
        idp_total_count = 0
    
    return render_template(
        "views/admin.html", 
        config=current_app.config,
        passkey_count=passkey_count,
        passkey_ui_count=passkey_ui_count,
        passkey_js_count=passkey_js_count,
        mfa_count=mfa_count,
        password_count=password_count,
        passkey_analyzed_count=passkey_analyzed_count,
        passkey_detected_count=passkey_detected_count,
        google_count=google_count,
        microsoft_count=microsoft_count,
        apple_count=apple_count,
        github_count=github_count,
        idp_total_count=idp_total_count
    )


@bp_views.get("/info")
def info():
    return send_from_directory("./static", "info.html")


@bp_views.get("/code")
def code():
    return send_from_directory("./static", "code.zip")


@bp_views.get("/paper.pdf")
def paper():
    return send_from_directory("./static", "paper.pdf", as_attachment=True)


@bp_views.get("/paper.bib")
def bib():
    return send_from_directory("./static", "paper.bib", as_attachment=True)


@bp_views.get("/disclaimer")
def disclaimer():
    return render_template("views/disclaimer.html")
