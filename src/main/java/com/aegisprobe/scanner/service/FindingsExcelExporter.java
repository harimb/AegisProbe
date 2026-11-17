package com.aegisprobe.scanner.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import com.aegisprobe.scanner.domain.Finding;
import com.aegisprobe.scanner.domain.Severity;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.xssf.usermodel.XSSFColor;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import org.springframework.stereotype.Component;

/**
 * Exports a scan's findings as a styled {@code .xlsx} workbook: one header row and
 * one row per finding, with the severity cell coloured to match the report.
 */
@Component
public class FindingsExcelExporter {

    private static final String[] HEADERS =
            {"Severity", "OWASP Category", "Finding", "Method", "URL", "Evidence", "Fix"};

    private static final Map<Severity, byte[]> SEVERITY_RGB = new EnumMap<>(Severity.class);

    static {
        SEVERITY_RGB.put(Severity.HIGH, new byte[]{(byte) 220, (byte) 38, (byte) 38});
        SEVERITY_RGB.put(Severity.MEDIUM, new byte[]{(byte) 217, (byte) 119, (byte) 6});
        SEVERITY_RGB.put(Severity.LOW, new byte[]{(byte) 37, (byte) 99, (byte) 235});
        SEVERITY_RGB.put(Severity.INFO, new byte[]{(byte) 100, (byte) 116, (byte) 139});
    }

    /** Builds the workbook bytes for the given target and findings. */
    public byte[] toXlsx(String target, List<Finding> findings) {
        try (XSSFWorkbook workbook = new XSSFWorkbook();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            Sheet sheet = workbook.createSheet("Findings");
            writeHeader(workbook, sheet);

            Map<Severity, CellStyle> severityStyles = severityStyles(workbook);
            CellStyle wrap = workbook.createCellStyle();
            wrap.setWrapText(true);

            int rowNum = 1;
            for (Finding f : findings) {
                Row row = sheet.createRow(rowNum++);
                Cell severity = row.createCell(0);
                severity.setCellValue(f.getSeverity().name());
                severity.setCellStyle(severityStyles.get(f.getSeverity()));
                row.createCell(1).setCellValue(f.getOwaspCategory());
                row.createCell(2).setCellValue(f.getTitle());
                row.createCell(3).setCellValue(f.getMethod());
                row.createCell(4).setCellValue(f.getUrl());
                cell(row, 5, f.getEvidence(), wrap);
                cell(row, 6, f.getRemediation(), wrap);
            }

            sizeColumns(sheet);
            sheet.createFreezePane(0, 1);

            workbook.write(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to build findings spreadsheet", e);
        }
    }

    private void writeHeader(XSSFWorkbook workbook, Sheet sheet) {
        CellStyle headerStyle = workbook.createCellStyle();
        Font bold = workbook.createFont();
        bold.setBold(true);
        headerStyle.setFont(bold);
        headerStyle.setFillForegroundColor(IndexedColors.GREY_25_PERCENT.getIndex());
        headerStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

        Row header = sheet.createRow(0);
        for (int i = 0; i < HEADERS.length; i++) {
            Cell cell = header.createCell(i);
            cell.setCellValue(HEADERS[i]);
            cell.setCellStyle(headerStyle);
        }
    }

    private Map<Severity, CellStyle> severityStyles(XSSFWorkbook workbook) {
        Font white = workbook.createFont();
        white.setBold(true);
        white.setColor(IndexedColors.WHITE.getIndex());

        Map<Severity, CellStyle> styles = new EnumMap<>(Severity.class);
        SEVERITY_RGB.forEach((severity, rgb) -> {
            CellStyle style = workbook.createCellStyle();
            style.setFont(white);
            style.setFillForegroundColor(new XSSFColor(rgb, null));
            style.setFillPattern(FillPatternType.SOLID_FOREGROUND);
            styles.put(severity, style);
        });
        return styles;
    }

    private void cell(Row row, int index, String value, CellStyle style) {
        Cell cell = row.createCell(index);
        cell.setCellValue(value == null ? "" : value);
        cell.setCellStyle(style);
    }

    private void sizeColumns(Sheet sheet) {
        int[] widthsInChars = {12, 30, 44, 8, 46, 60, 60};
        for (int i = 0; i < widthsInChars.length; i++) {
            sheet.setColumnWidth(i, widthsInChars[i] * 256);
        }
    }
}
