from django.db import models
from django.core.validators import RegexValidator
from datetime import date


class AllowedCVE(models.Model):
    class Reason(models.TextChoices):
        ACCEPTED = 'accepted', 'Risk accepted'
        NOT_APPLICABLE = 'notapplicable', 'Not applicable'
        UNFIXED = 'unfixed', 'Editor will not fix'
        FALSEPOSITIVE = 'falsepositive', 'False positive'

    CVE_ID_VALIDATOR: RegexValidator = RegexValidator(
            regex='^CVE-\d{4}-\d{4,11}$',
            message='Invalid CVE ID format',
        )

    cve_id = models.CharField(
        max_length=20,
        primary_key=True,
        validators=[CVE_ID_VALIDATOR]
    )

    added_by = models.CharField(
        max_length=40,
        default='Anonymous'
    )
    date = models.DateField(
        default=date.today
    )
    reason = models.CharField(
        max_length=13,
        choices=Reason.choices,
        default=Reason.ACCEPTED
    )
    comment = models.TextField(
        blank=True
    )
