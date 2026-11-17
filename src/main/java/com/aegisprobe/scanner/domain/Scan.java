package com.aegisprobe.scanner.domain;

import java.time.OffsetDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "scan")
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "target_url", nullable = false)
    private String targetUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status = ScanStatus.PENDING;

    @Column(name = "authorized_by", nullable = false)
    private String authorizedBy;

    @Column(name = "endpoints_seen", nullable = false)
    private int endpointsSeen;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "started_at", nullable = false)
    private OffsetDateTime startedAt = OffsetDateTime.now();

    @Column(name = "finished_at")
    private OffsetDateTime finishedAt;

    protected Scan() {
    }

    public Scan(String targetUrl, String authorizedBy) {
        this.targetUrl = targetUrl;
        this.authorizedBy = authorizedBy;
    }

    public Long getId() {
        return id;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public String getAuthorizedBy() {
        return authorizedBy;
    }

    public int getEndpointsSeen() {
        return endpointsSeen;
    }

    public void setEndpointsSeen(int endpointsSeen) {
        this.endpointsSeen = endpointsSeen;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public OffsetDateTime getStartedAt() {
        return startedAt;
    }

    public OffsetDateTime getFinishedAt() {
        return finishedAt;
    }

    public void setFinishedAt(OffsetDateTime finishedAt) {
        this.finishedAt = finishedAt;
    }
}
