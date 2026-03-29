from django.contrib import admin
from .models import AnalysisSession


@admin.register(AnalysisSession)
class AnalysisSessionAdmin(admin.ModelAdmin):
    list_display  = ('session_id', 'source_type', 'status', 'total_flows',
                     'malicious_flows', 'started_at', 'completed_at')
    list_filter   = ('source_type', 'status')
    readonly_fields = ('session_id', 'started_at', 'completed_at')
    search_fields = ('session_id', 'pcap_file_name', 'interface_name')
