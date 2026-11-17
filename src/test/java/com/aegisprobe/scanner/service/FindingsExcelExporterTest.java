package com.aegisprobe.scanner.service;

import java.io.ByteArrayInputStream;
import java.util.List;

import com.aegisprobe.scanner.domain.Finding;
import com.aegisprobe.scanner.domain.Severity;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FindingsExcelExporterTest {

    private final FindingsExcelExporter exporter = new FindingsExcelExporter();

    @Test
    void writesHeaderAndOneRowPerFinding() throws Exception {
        List<Finding> findings = List.of(
                new Finding(1L, "A05 Security Misconfiguration", Severity.MEDIUM,
                        "No Content-Security-Policy header", "http://localhost:8080", "GET",
                        "Response has no CSP header.", "Add a CSP header."),
                new Finding(1L, "A02 Cryptographic Failures", Severity.LOW,
                        "Cleartext HTTP", "http://localhost:8080", "GET",
                        "Served over http.", "Use HTTPS."));

        byte[] bytes = exporter.toXlsx("http://localhost:8080", findings);

        try (Workbook workbook = WorkbookFactory.create(new ByteArrayInputStream(bytes))) {
            Sheet sheet = workbook.getSheetAt(0);

            Row header = sheet.getRow(0);
            assertEquals("Severity", header.getCell(0).getStringCellValue());
            assertEquals("OWASP Category", header.getCell(1).getStringCellValue());
            assertEquals("Finding", header.getCell(2).getStringCellValue());
            assertEquals("Method", header.getCell(3).getStringCellValue());
            assertEquals("URL", header.getCell(4).getStringCellValue());
            assertEquals("Evidence", header.getCell(5).getStringCellValue());
            assertEquals("Fix", header.getCell(6).getStringCellValue());

            Row first = sheet.getRow(1);
            assertEquals("MEDIUM", first.getCell(0).getStringCellValue());
            assertEquals("A05 Security Misconfiguration", first.getCell(1).getStringCellValue());
            assertEquals("No Content-Security-Policy header", first.getCell(2).getStringCellValue());
            assertEquals("GET", first.getCell(3).getStringCellValue());
            assertEquals("http://localhost:8080", first.getCell(4).getStringCellValue());

            // header + 2 data rows => last row index is 2
            assertEquals(2, sheet.getLastRowNum());
        }
    }

    @Test
    void writesHeaderOnlyWhenNoFindings() throws Exception {
        byte[] bytes = exporter.toXlsx("http://localhost:8080", List.of());

        try (Workbook workbook = WorkbookFactory.create(new ByteArrayInputStream(bytes))) {
            Sheet sheet = workbook.getSheetAt(0);
            assertEquals(0, sheet.getLastRowNum());
            assertEquals("Severity", sheet.getRow(0).getCell(0).getStringCellValue());
        }
    }
}
