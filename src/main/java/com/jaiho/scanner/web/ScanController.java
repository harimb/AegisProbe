package com.jaiho.scanner.web;

import com.jaiho.scanner.service.FindingsExcelExporter;
import com.jaiho.scanner.service.ScanNotAllowedException;
import com.jaiho.scanner.service.ScanProgressStore;
import com.jaiho.scanner.service.ScanService;
import com.jaiho.scanner.service.ScanSummary;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Web endpoints for the security scanner. All of these require a logged-in user
 * (everything outside the public pages does, per SecurityConfig).
 */
@Controller
public class ScanController {

    private final ScanService scanService;
    private final ScanProgressStore progressStore;
    private final FindingsExcelExporter excelExporter;

    public ScanController(ScanService scanService, ScanProgressStore progressStore,
                          FindingsExcelExporter excelExporter) {
        this.scanService = scanService;
        this.progressStore = progressStore;
        this.excelExporter = excelExporter;
    }

    @GetMapping("/scan")
    public String form(Model model) {
        model.addAttribute("scans", scanService.recentScans());
        model.addAttribute("allowedHosts", scanService.allowedHosts());
        return "scan";
    }

    @PostMapping("/scan")
    public String start(@RequestParam String targetUrl,
                        @RequestParam(defaultValue = "false") boolean authorized,
                        @RequestParam(defaultValue = "false") boolean activeScan,
                        Principal principal,
                        RedirectAttributes redirectAttributes) {
        try {
            Long id = scanService.startScan(targetUrl, authorized, activeScan, principal.getName());
            return "redirect:/scan/" + id;
        } catch (ScanNotAllowedException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            redirectAttributes.addFlashAttribute("targetUrl", targetUrl);
            return "redirect:/scan";
        }
    }

    /** Deletes one or more scans (running scans are cancelled, then removed). */
    @PostMapping("/scan/delete")
    public String delete(@RequestParam(name = "ids", required = false) List<Long> ids,
                         RedirectAttributes redirectAttributes) {
        if (ids == null || ids.isEmpty()) {
            redirectAttributes.addFlashAttribute("message", "No scans selected.");
            return "redirect:/scan";
        }
        int deleted = scanService.deleteScans(ids);
        redirectAttributes.addFlashAttribute("message",
                deleted + (deleted == 1 ? " scan deleted." : " scans deleted."));
        return "redirect:/scan";
    }

    @GetMapping("/scan/{id}")
    public String report(@PathVariable Long id, Model model) {
        ScanSummary summary = scanService.getSummary(id).orElse(null);
        if (summary == null) {
            return "redirect:/scan";
        }
        model.addAttribute("summary", summary);
        model.addAttribute("scan", summary.scan());
        return "scan-report";
    }

    /** Polled by the report page while a scan is still running. */
    @GetMapping("/scan/{id}/status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> status(@PathVariable Long id) {
        return scanService.getSummary(id)
                .map(s -> {
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("status", s.scan().getStatus().name());
                    body.put("total", s.total());
                    body.put("endpoints", s.scan().getEndpointsSeen());
                    progressStore.find(id).ifPresent(p -> {
                        body.put("phase", p.getPhase());
                        body.put("percent", p.getPercent());
                        body.put("log", p.getLog());
                    });
                    return ResponseEntity.ok(body);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /** Excel (.xlsx) export of a scan's findings. */
    @GetMapping("/scan/{id}/export.xlsx")
    @ResponseBody
    public ResponseEntity<byte[]> exportExcel(@PathVariable Long id) {
        return scanService.getSummary(id)
                .map(s -> {
                    byte[] bytes = excelExporter.toXlsx(s.scan().getTargetUrl(), s.findings());
                    return ResponseEntity.ok()
                            .header(HttpHeaders.CONTENT_DISPOSITION,
                                    "attachment; filename=\"scan-" + id + ".xlsx\"")
                            .contentType(MediaType.parseMediaType(
                                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                            .body(bytes);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /** Machine-readable export of a scan's findings. */
    @GetMapping("/scan/{id}/export.json")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> export(@PathVariable Long id) {
        return scanService.getSummary(id)
                .map(s -> {
                    List<Map<String, Object>> items = s.findings().stream()
                            .map(f -> Map.<String, Object>of(
                                    "category", f.getOwaspCategory(),
                                    "severity", f.getSeverity().name(),
                                    "title", f.getTitle(),
                                    "url", f.getUrl(),
                                    "method", f.getMethod(),
                                    "evidence", f.getEvidence() == null ? "" : f.getEvidence(),
                                    "remediation", f.getRemediation() == null ? "" : f.getRemediation()))
                            .toList();
                    return ResponseEntity.ok(Map.<String, Object>of(
                            "target", s.scan().getTargetUrl(),
                            "status", s.scan().getStatus().name(),
                            "findings", items));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
