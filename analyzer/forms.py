from django import forms

class UploadSolutionZipForm(forms.Form):
    project_id = forms.CharField(
        label="Project ID",
        required=False,
        max_length=80,
    )
    solution_zip = forms.FileField(
        label="Solution ZIP (.zip)",
        required=True,
    )
