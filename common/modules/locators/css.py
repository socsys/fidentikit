import logging
from typing import List
from playwright.sync_api import Page
from common.modules.helper.locator import LocatorHelper


logger = logging.getLogger(__name__)


class CSSLocator:


    # https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes
    attributes_high_validity = [
        "title", "aria-label", "value", "id", "alt", "label", "name", "placeholder"
    ]
    attributes_low_validity = [
        "title", "aria-label", "value", "id", "alt", "label", "name", "placeholder", "class", "action", "href", "data"
    ]
    # https://developer.mozilla.org/en-US/docs/Web/HTML/Element
    tags_to_exclude = [
        "script", "html", "body", "head", "noscript"
    ]


    def __init__(
        self,
        keywords: List[str],
        high_validity_patterns: List[str] = []
    ):
        # keyword to search (i.e., "google", "login", ...)
        self.keywords = [k.lower() for k in keywords]
        # high validity patterns in which %s is replaced with keyword (i.e., ["login with %s", ...])
        self.high_validity_patterns = [p.lower() for p in high_validity_patterns]

        # keywords to search for in text and attributes of elements
        self.low_validity_keywords = self.keywords
        self.high_validity_keywords = [p.replace("%s", k) for k in self.keywords for p in self.high_validity_patterns]

        # css locator
        self.low_validity_locator = self.get_css_locator(
            self.low_validity_keywords,
            self.attributes_low_validity,
            self.tags_to_exclude
        )
        self.high_validity_locator = self.get_css_locator(
            self.high_validity_keywords,
            self.attributes_high_validity,
            self.tags_to_exclude
        )


    def locate(self, page: Page, high_validity: bool) -> List[dict]:
        logger.info(f"Locating elements with css locator ({'high' if high_validity else 'low'} validity)")

        logger.info(f"Getting element candidates")
        try:
            if high_validity:
                locator_str = self.high_validity_locator
            else:
                locator_str = self.low_validity_locator
            
            if not locator_str or locator_str.strip() == "":
                logger.warning("Empty CSS locator, returning empty list")
                return []
            
            element_candidates = page.locator(locator_str).all()
        except Exception as e:
            logger.error(f"Error creating locator: {e}")
            logger.debug(f"Locator string was: {locator_str if 'locator_str' in locals() else 'N/A'}")
            return []
        
        logger.info(f"#{len(element_candidates)} element candidates found")

        logger.info(f"Filtering element candidates")
        elements = []
        for i, e in enumerate(element_candidates[:100]):
            logger.info(f"Checking element candidate {i+1} of {len(element_candidates)})")
            el_valid, el_loc, el_info = LocatorHelper.get_element_metadata(e)
            if el_valid:
                logger.info(f"Element candidate {i+1} is valid")
                elements.append(el_info)
            else:
                logger.info(f"Element candidate {i+1} is invalid")
        logger.info(f"#{len(elements)} filtered element candidates found")

        return elements


    @staticmethod
    def get_css_locator(keywords: List[str], attributes: List[str], tags_to_exclude: List[str]) -> str:
        if not keywords:
            return "body"  # Return a safe default selector if no keywords
        
        locs = []
        # smallest element containing specified text, case-insensitive, trims whitespace, substring
        locs.extend([f':text("{kw}"):not({",".join(tags_to_exclude)})' for kw in keywords if kw])
        # case-insensitive, substring
        locs.extend([f'[{attr}*="{kw}" i]:not({",".join(tags_to_exclude)})' for kw in keywords if kw for attr in attributes])
        
        # If no valid locators generated, return a safe default
        if not locs:
            return "body"
        
        # match all elements that can be selected by one of the selectors
        return ", ".join(locs)
