from django.contrib import admin
from django.utils import timezone 
from .models import Profile, Category, Complaint
from django.contrib import admin
from .models import Complaint


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role')

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)

# portal/admin.py


@admin.register(Complaint)
class ComplaintAdmin(admin.ModelAdmin):
    list_display = ('id', 'category', 'status', 'created_at', 'resolved_at')
    list_filter = ('status', 'category')
    search_fields = ('description',)
    readonly_fields = ('created_at', 'resolved_at')

    # Optional: add actions to mark complaints as resolved
    actions = ['mark_resolved']

    def mark_resolved(self, request, queryset):
        updated = queryset.update(status='Resolved', resolved_at=timezone.now())
        self.message_user(request, f"{updated} complaint(s) marked as resolved.")
    mark_resolved.short_description = "Mark selected complaints as resolved"

