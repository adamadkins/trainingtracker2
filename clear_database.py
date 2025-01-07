from app import app, db, User, TrainingAssignment, TrainingSession, Notification, Comment, TeamMember, Position

def clear_database():
    try:
        print("Clearing database...")

        # Delete all training assignments
        db.session.query(TrainingAssignment).delete()

        # Delete all training sessions
        db.session.query(TrainingSession).delete()

        # Delete all notifications
        db.session.query(Notification).delete()

        # Delete all comments
        db.session.query(Comment).delete()

        # Delete all team members
        db.session.query(TeamMember).delete()

        # Delete all positions
        db.session.query(Position).delete()

        # Delete all users except the default admin
        default_admin_email = "admin@example.com"  # Update with the admin's email
        db.session.query(User).filter(User.email != default_admin_email).delete()

        # Commit changes
        db.session.commit()
        print("Database cleared successfully! Default admin retained.")
    except Exception as e:
        db.session.rollback()
        print(f"Error clearing database: {e}")

if __name__ == "__main__":
    with app.app_context():  # Set up the Flask application context
        clear_database()
