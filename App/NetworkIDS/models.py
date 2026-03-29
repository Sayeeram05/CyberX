"""
NetworkIDS Models — persists analysis sessions so the polling endpoint
can return incremental progress updates.
"""

import uuid
from django.db import models


class AnalysisSession(models.Model):
    """Tracks one NIDS analysis run (PCAP upload or live capture)."""

    SOURCE_CHOICES = [
        ('pcap_upload', 'PCAP File Upload'),
        ('live_capture', 'Live Packet Capture'),
    ]

    STATUS_CHOICES = [
        ('pending',    'Pending'),
        ('capturing',  'Capturing Packets'),
        ('analyzing',  'Analyzing Flows'),
        ('complete',   'Complete'),
        ('error',      'Error'),
    ]

    session_id      = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source_type     = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='pcap_upload')
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    pcap_file_name  = models.CharField(max_length=255, blank=True, default='')
    interface_name  = models.CharField(max_length=64,  blank=True, default='')
    capture_duration= models.IntegerField(default=10)   # seconds (live capture)

    total_flows     = models.IntegerField(default=0)
    malicious_flows = models.IntegerField(default=0)

    # JSON array of per-flow result dicts
    results_json    = models.TextField(default='[]')

    started_at      = models.DateTimeField(auto_now_add=True)
    completed_at    = models.DateTimeField(null=True, blank=True)
    error_message   = models.TextField(blank=True, default='')

    class Meta:
        ordering = ['-started_at']
        verbose_name = 'Analysis Session'
        verbose_name_plural = 'Analysis Sessions'

    def __str__(self):
        return f"{self.get_source_type_display()} | {self.status} | {self.started_at:%Y-%m-%d %H:%M}"
