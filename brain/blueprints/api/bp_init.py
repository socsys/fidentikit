# Database initialization script to create necessary indexes
import logging

logger = logging.getLogger(__name__)

def initialize_database(db):
    """
    Initialize the database with required indexes.
    This is called when the application starts.
    """
    try:
        # Create indexes for ground_truth
        logger.info("Creating indexes for ground_truth...")
        db.ground_truth.create_index("gt_id")
        db.ground_truth.create_index("domain")
        db.ground_truth.create_index("rank")
        
        # Create indexes for landscape_analysis
        logger.info("Creating indexes for landscape_analysis...")
        db.landscape_analysis.create_index("domain")
        db.landscape_analysis.create_index("scan_config.scan_id")
        db.landscape_analysis.create_index("task_config.task_id")
        db.landscape_analysis.create_index("task_config.task_timestamp_request_sent")
        db.landscape_analysis.create_index("landscape_analysis_result.identity_providers.idp_name")
        db.landscape_analysis.create_index("landscape_analysis_result.authentication_mechanisms.passkey.detected")
        db.landscape_analysis.create_index("landscape_analysis_result.authentication_mechanisms.mfa.detected")
        db.landscape_analysis.create_index("landscape_analysis_result.authentication_mechanisms.password.detected")
        db.landscape_analysis.create_index("landscape_analysis_result.metadata_available.passkey_endpoints")
        
        # Create indexes for top_sites_list
        logger.info("Creating indexes for top_sites_list...")
        db.top_sites_lists.create_index("id")
        db.top_sites_lists.create_index("rank")
        db.top_sites_lists.create_index("domain")
        
        # Create indexes for passkey_analysis
        logger.info("Creating indexes for passkey_analysis...")
        db.passkey_analysis.create_index("domain")
        db.passkey_analysis.create_index("scan_config.scan_id")
        db.passkey_analysis.create_index("task_config.task_id")
        db.passkey_analysis.create_index("task_config.task_timestamp_request_sent")
        db.passkey_analysis.create_index("passkey_analysis_result.passkey.detected")
        db.passkey_analysis.create_index("passkey_analysis_result.passkey.implementation.create_options.challenge")
        db.passkey_analysis.create_index("passkey_analysis_result.passkey.implementation.create_options.rp.id")
        db.passkey_analysis.create_index("passkey_analysis_result.passkey.implementation.get_options.challenge")
        db.passkey_analysis.create_index("passkey_analysis_result.passkey.implementation.get_options.rpId")
        
        logger.info("Database initialization completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False 