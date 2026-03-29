from django.db import models
from django.utils import timezone


class EmailValidationLog(models.Model):
    """Logs every email validation request for behavioral analysis."""
    email = models.EmailField(db_index=True)
    domain = models.CharField(max_length=255, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    is_valid = models.BooleanField(default=False)
    is_temporary = models.BooleanField(default=False)
    is_deliverable = models.BooleanField(default=False)
    risk_score = models.FloatField(default=0)
    risk_level = models.CharField(max_length=20, default='unknown')
    threat_level = models.CharField(max_length=20, default='none')
    spf_status = models.CharField(max_length=50, null=True, blank=True)
    dkim_status = models.CharField(max_length=50, null=True, blank=True)
    dmarc_status = models.CharField(max_length=50, null=True, blank=True)
    domain_age_days = models.IntegerField(null=True, blank=True)
    processing_time_ms = models.FloatField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['domain', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.email} — risk:{self.risk_score} @ {self.timestamp:%Y-%m-%d %H:%M}"


class DomainCache(models.Model):
    """Caches WHOIS + DNS authentication results per domain (TTL: 7 days)."""
    domain = models.CharField(max_length=255, unique=True, db_index=True)

    # WHOIS data
    creation_date = models.DateTimeField(null=True, blank=True)
    registrar = models.CharField(max_length=255, null=True, blank=True)
    whois_country = models.CharField(max_length=10, null=True, blank=True)

    # SPF
    spf_record = models.TextField(null=True, blank=True)
    spf_found = models.BooleanField(default=False)
    spf_strictness = models.CharField(max_length=20, null=True, blank=True)

    # DKIM
    dkim_found = models.BooleanField(default=False)
    dkim_selector = models.CharField(max_length=100, null=True, blank=True)

    # DMARC
    dmarc_record = models.TextField(null=True, blank=True)
    dmarc_found = models.BooleanField(default=False)
    dmarc_policy = models.CharField(max_length=20, null=True, blank=True)

    last_checked = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Domain caches"

    @property
    def is_expired(self):
        if not self.last_checked:
            return True
        return (timezone.now() - self.last_checked).days >= 7

    @property
    def age_days(self):
        if not self.creation_date:
            return None
        return (timezone.now() - self.creation_date).days

    def __str__(self):
        return f"{self.domain} (cached {self.last_checked:%Y-%m-%d})"


class BehavioralFlag(models.Model):
    """Stores anomaly flags from behavioral monitoring."""
    FLAG_TYPES = [
        ('bulk_temp_check', 'Bulk Temporary Email Checking'),
        ('rate_limit', 'Rate Limit Exceeded'),
        ('domain_abuse', 'Domain Abuse Pattern'),
        ('suspicious_pattern', 'Suspicious Query Pattern'),
    ]

    domain = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    flag_type = models.CharField(max_length=30, choices=FLAG_TYPES)
    severity = models.CharField(max_length=10, default='low')  # low, medium, high
    details = models.TextField()
    resolved = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity}] {self.flag_type} — {self.ip_address or self.domain} @ {self.timestamp:%Y-%m-%d %H:%M}"
