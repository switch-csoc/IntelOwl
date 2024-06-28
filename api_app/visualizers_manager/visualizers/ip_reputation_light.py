from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import (
    VisualizableColor,
    VisualizableIcon,
    VisualizableSize,
)

logger = getLogger(__name__)

#make meta data list wider, add new data

class IPLight(Visualizer):
    @visualizable_error_handler_with_params("IPQS")
    def _ipqs(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="IPQS_Fraud_And_Risk_Scoring"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("IPQS_Fraud_And_Risk_Scoring report does not exist")
        else:
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            country = analyzer_report.report.get("country_code", "")
            region = analyzer_report.report.get("region", "")
            city = analyzer_report.report.get("city", "")
            isp_name = analyzer_report.report.get("ISP", "")
            asn_number = analyzer_report.report.get("ASN", "")
            organization_name = analyzer_report.report.get("organization", "")

            location = f"{city}, {region}, {country}"
            organization = f"Organization: {organization_name}"
            isp = f"ISP: {isp_name}"
            asn = f"ASN {asn_number}"

            vpn = analyzer_report.report.get("vpn", False)
            tor = analyzer_report.report.get("tor", False)
            fraud_score = analyzer_report.report.get("fraud_score", 0)
            meta = [location,isp,organization,asn]
            meta_data = self.VList(
                name=self.Base(
                    value="IP Meta Data",
                    color= VisualizableColor.PRIMARY,
                ),
                value=[self.Base(s) for s in meta],
                start_open=True,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )
            report_data = self.Title(
                self.Base(
                    value="IPQS",
                    icon= VisualizableIcon.FIRE
                ),
                
                self.Base(value=f"Fraud Score - {fraud_score}/100"),
                disable=disabled,
            )
            vpn_data = self.Bool(
                value="VPN",
                disable= (vpn == False or disabled),
            )
            tor_data = self.Bool(
                value="TOR",
                disable= (tor == False or disabled),
            )
            
            return meta_data, report_data, vpn_data, tor_data


    @visualizable_error_handler_with_params("VirusTotal")
    def _vt3(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="VirusTotal_v3_Get_Observable"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("VirusTotal_v3_Get_Observable report does not exist")
        else:
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            malicious_hits = (
                analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )
            sus_hits = (
                analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("suspicious",0)
            )
            num_vendors = (
                analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("harmless", 0)
            ) + (analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("undetected", 0)
            )
           
            hits = malicious_hits + sus_hits
            virustotal_report = self.Title(
                self.Base(
                    value="VirusTotal",
                    link=analyzer_report.report["link"],
                    icon=VisualizableIcon.VIRUSTotal,
                ),
                
                self.Base(value=f"Engine Hits: {hits}/{num_vendors}"),
                disable=disabled,
            )
            virustotal_malicious = self.Bool(
                value="Malicious",
                disable= (malicious_hits == 0 or disabled),
            )
            virustotal_suspicious = self.Bool(
                value="Suspicious",
                disable= (sus_hits == 0 or disabled),
            )
            return virustotal_report, virustotal_malicious, virustotal_suspicious
        
    @visualizable_error_handler_with_params("AbuseIPDB Categories")
    def _abuse_ipdb(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="AbuseIPDB")
        except AnalyzerReport.DoesNotExist:
            logger.warning("AbuseIPDB report does not exist")
            return None, None
        else:
            data = analyzer_report.report.get("data", [])
            isp = data.get("isp", "")
            usage = data.get("usageType", "")
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            abuse_report = self.Title(
                self.Base(
                    value="AbuseIPDB",
                    link=analyzer_report.report.get("permalink", ""),
                ),
                self.Base(value=f"ISP: {isp} ({usage})"),
                disable=disabled,
            )

            categories_extracted = []
            for c in data.get("reports", []):
                categories_extracted.extend(c.get("categories_human_readable", []))
            categories_extracted = list(set(categories_extracted))
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or not categories_extracted
            )
            abuse_categories_report = self.VList(
                name=self.Base(
                    value="AbuseIPDB Categories",
                    icon=VisualizableIcon.ALARM,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[self.Base(c, disable=disabled) for c in categories_extracted],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )

            return abuse_report, abuse_categories_report

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements =[]
        fourth_level_elements = []

        meta_data_ipqs, report_ipqs, vpn_data_ipqs, tor_data_ipqs = self._ipqs()
        first_level_elements.append(meta_data_ipqs)
        second_level_elements.append(report_ipqs)
        third_level_elements.append(vpn_data_ipqs)
        third_level_elements.append(tor_data_ipqs)

        vt_report, vt_malicious, vt_suspicious = self._vt3()
        second_level_elements.append(vt_report)
        third_level_elements.append(vt_malicious)
        third_level_elements.append(vt_suspicious)

        abuse_report, abuse_categories_report = self._abuse_ipdb()

        page = self.Page(name="IP Reputation")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=first_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=second_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_2,
                horizontal_list=self.HList(value=third_level_elements),
            )
        )
       
        

        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
