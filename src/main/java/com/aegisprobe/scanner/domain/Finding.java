package com.aegisprobe.scanner.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One issue found during a scan. Each finding belongs to a {@link Scan} through
 * {@code scanId} (a plain foreign key rather than a mapped relationship, to keep
 * loading simple).
 */
@Entity
@Table(name = "finding")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "owasp_category", nullable = false)
    private String owaspCategory;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String url;

    @Column(nullable = false)
    private String method;

    @Column
    private String evidence;

    @Column
    private String remediation;

    protected Finding() {
    }

    public Finding(Long scanId, String owaspCategory, Severity severity, String title,
                   String url, String method, String evidence, String remediation) {
        this.scanId = scanId;
        this.owaspCategory = owaspCategory;
        this.severity = severity;
        this.title = title;
        this.url = url;
        this.method = method;
        this.evidence = evidence;
        this.remediation = remediation;
    }

    public Long getId() {
        return id;
    }

    public Long getScanId() {
        return scanId;
    }

    public String getOwaspCategory() {
        return owaspCategory;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getUrl() {
        return url;
    }

    public String getMethod() {
        return method;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getRemediation() {
        return remediation;
    }
}
