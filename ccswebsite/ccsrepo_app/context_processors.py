from .models import AdviserStudentRelationship, ManuscriptAccessRequest, Manuscript

def pending_requests_counts(request):
    # Ensure the user is authenticated
    if request.user.is_authenticated:
        # Count pending student approvals where the logged-in user is the adviser
        pending_student_approvals = AdviserStudentRelationship.objects.filter(
            adviser=request.user, status='pending'
        ).count()

        # Count pending manuscript access requests where the manuscript's adviser is the logged-in user
        pending_access_requests = ManuscriptAccessRequest.objects.filter(
            manuscript__adviser=request.user, status='pending'
        ).count()

        # Uncomment the below section if manuscript reviews are also tied to the adviser
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