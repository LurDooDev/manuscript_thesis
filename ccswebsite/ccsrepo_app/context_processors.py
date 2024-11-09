from .models import AdviserStudentRelationship, ManuscriptAccessRequest, Manuscript

def pending_requests_counts(request):
    # Ensure the user is authenticated
    if request.user.is_authenticated:
        # Count the pending student approvals where the logged-in user is the adviser
        pending_student_approvals = AdviserStudentRelationship.objects.filter(
            adviser=request.user, status='pending'
        ).count()

        # Count the pending manuscript access requests
        pending_access_requests = ManuscriptAccessRequest.objects.filter(status='pending').count()

        # # Count the pending manuscript reviews where the logged-in user is the adviser
        # pending_manuscript_reviews = Manuscript.objects.filter(
        #     reviewer=request.user, status='pending'
        # ).count()

        return {
            'pending_student_approvals': pending_student_approvals,
            'pending_access_requests': pending_access_requests,
            # 'pending_manuscript_reviews': pending_manuscript_reviews,  # Add the count for pending manuscript reviews
        }

    # Return zero counts if the user is not authenticated
    return {
        'pending_student_approvals': 0,
        'pending_access_requests': 0,
        # 'pending_manuscript_reviews': 0,
    }