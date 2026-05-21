use super::config::UsernameOsintResult;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_markdown(result: &UsernameOsintResult) -> String {
        let mut md = String::new();

        md.push_str(&format!("# Username OSINT Report: {}\n\n", result.username));
        md.push_str(&format!("**Digital Footprint Score**: {:.0}/100\n\n", result.digital_footprint_score));
        md.push_str(&format!("**Risk Level**: {}\n\n", result.risk_level));
        md.push_str(&format!("**Summary**: {}\n\n", result.summary));

        md.push_str("## Statistics\n\n");
        md.push_str(&format!("- **Found**: {} platforms\n", result.total_found));
        md.push_str(&format!("- **Not Found**: {} platforms\n", result.total_checked - result.total_found - result.total_errors));
        md.push_str(&format!("- **Errors**: {} platforms\n", result.total_errors));
        md.push_str(&format!("- **Total Checked**: {} platforms\n\n", result.total_checked));

        if !result.found_on.is_empty() {
            md.push_str("## Found Accounts\n\n");
            md.push_str("| Platform | URL | Category | Detection Method |\n");
            md.push_str("|----------|-----|----------|-----------------|\n");
            for p in &result.found_on {
                md.push_str(&format!(
                    "| {} | [{}]({}) | {} | {} |\n",
                    p.platform, p.url, p.url, p.category,
                    p.detection_method.as_deref().unwrap_or("-")
                ));
            }
            md.push('\n');
        }

        if !result.extracted_ids.is_empty() {
            md.push_str("## Extracted IDs\n\n");
            md.push_str("| ID Value | ID Type | Source Platform |\n");
            md.push_str("|----------|---------|----------------|\n");
            for id in &result.extracted_ids {
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    id.id_value, id.id_type, id.source_platform
                ));
            }
            md.push('\n');
        }

        if !result.recursive_results.is_empty() {
            md.push_str("## Recursive Search Results\n\n");
            for r in &result.recursive_results {
                md.push_str(&format!(
                    "### {} ({}: {}, depth: {})\n\n",
                    r.id_value, r.id_type, r.source_platform, r.depth
                ));
                md.push_str(&format!(
                    "Found on {} out of {} platforms.\n\n",
                    r.found_count, r.total_checked
                ));
                if !r.found_on.is_empty() {
                    for p in &r.found_on {
                        md.push_str(&format!("- **{}**: [{}]({})\n", p.platform, p.url, p.url));
                    }
                    md.push('\n');
                }
            }
        }

        if let Some(ref analysis) = result.error_analysis {
            md.push_str("## Error Analysis\n\n");
            md.push_str(&format!("- **Error Rate**: {:.1}%\n", analysis.error_rate));
            md.push_str(&format!("- **CAPTCHA**: {} platforms\n", analysis.captcha_count));
            md.push_str(&format!("- **Censored**: {} platforms\n", analysis.censored_count));
            md.push_str(&format!("- **Network Errors**: {} platforms\n\n", analysis.network_error_count));

            if !analysis.recommendations.is_empty() {
                md.push_str("### Recommendations\n\n");
                for rec in &analysis.recommendations {
                    md.push_str(&format!("- {}\n", rec));
                }
                md.push('\n');
            }
        }

        if !result.category_summary.is_empty() {
            md.push_str("## Category Summary\n\n");
            md.push_str("| Category | Found | Total |\n");
            md.push_str("|----------|-------|-------|\n");
            for cat in &result.category_summary {
                md.push_str(&format!("| {} | {} | {} |\n", cat.category, cat.found, cat.total));
            }
            md.push('\n');
        }

        md
    }

    pub fn generate_html(result: &UsernameOsintResult) -> String {
        let mut html = String::new();

        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Username OSINT Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
h2 { color: #16213e; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
.stat-card { background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.stat-value { font-size: 2em; font-weight: bold; color: #e94560; }
.stat-label { color: #666; font-size: 0.9em; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
th { background: #16213e; color: white; padding: 12px; text-align: left; }
td { padding: 10px 12px; border-bottom: 1px solid #eee; }
tr:hover { background: #f0f0f0; }
a { color: #0f3460; text-decoration: none; }
a:hover { text-decoration: underline; }
.risk-critical { color: #dc3545; }
.risk-high { color: #fd7e14; }
.risk-medium { color: #ffc107; }
.risk-low { color: #28a745; }
.found-badge { background: #28a745; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
.not-found-badge { background: #6c757d; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
.error-badge { background: #dc3545; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
.recursive-section { background: #f8f9fa; border-left: 4px solid #0f3460; padding: 15px; margin: 10px 0; border-radius: 4px; }
</style>
</head>
<body>
<div class="container">
"#);

        html.push_str(&format!("<h1>Username OSINT Report: {}</h1>\n", result.username));

        let risk_class = match result.risk_level.as_str() {
            "critical" => "risk-critical",
            "high" => "risk-high",
            "medium" => "risk-medium",
            _ => "risk-low",
        };

        html.push_str("<div class=\"stats\">\n");
        html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-value\">{:.0}</div><div class=\"stat-label\">Digital Footprint Score</div></div>\n", result.digital_footprint_score));
        html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-value {}>{}</div><div class=\"stat-label\">Risk Level</div></div>\n", risk_class, result.risk_level));
        html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Found</div></div>\n", result.total_found));
        html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Errors</div></div>\n", result.total_errors));
        html.push_str("</div>\n");

        if !result.found_on.is_empty() {
            html.push_str("<h2>Found Accounts</h2>\n");
            html.push_str("<table><tr><th>Platform</th><th>URL</th><th>Category</th><th>Status</th></tr>\n");
            for p in &result.found_on {
                html.push_str(&format!(
                    "<tr><td>{}</td><td><a href=\"{}\" target=\"_blank\">{}</a></td><td>{}</td><td><span class=\"found-badge\">Found</span></td></tr>\n",
                    p.platform, p.url, p.url, p.category
                ));
            }
            html.push_str("</table>\n");
        }

        if !result.extracted_ids.is_empty() {
            html.push_str("<h2>Extracted IDs</h2>\n");
            html.push_str("<table><tr><th>ID Value</th><th>ID Type</th><th>Source</th></tr>\n");
            for id in &result.extracted_ids {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    id.id_value, id.id_type, id.source_platform
                ));
            }
            html.push_str("</table>\n");
        }

        if !result.recursive_results.is_empty() {
            html.push_str("<h2>Recursive Search Results</h2>\n");
            for r in &result.recursive_results {
                html.push_str(&format!(
                    "<div class=\"recursive-section\"><h3>{} ({} from {}, depth: {})</h3><p>Found on {} out of {} platforms</p>\n",
                    r.id_value, r.id_type, r.source_platform, r.depth, r.found_count, r.total_checked
                ));
                if !r.found_on.is_empty() {
                    html.push_str("<ul>\n");
                    for p in &r.found_on {
                        html.push_str(&format!("<li><strong>{}</strong>: <a href=\"{}\" target=\"_blank\">{}</a></li>\n", p.platform, p.url, p.url));
                    }
                    html.push_str("</ul>\n");
                }
                html.push_str("</div>\n");
            }
        }

        if !result.category_summary.is_empty() {
            html.push_str("<h2>Category Summary</h2>\n");
            html.push_str("<table><tr><th>Category</th><th>Found</th><th>Total</th></tr>\n");
            for cat in &result.category_summary {
                html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n", cat.category, cat.found, cat.total));
            }
            html.push_str("</table>\n");
        }

        html.push_str("</div></body></html>");
        html
    }
}
