import pandas as pd

def get_likes_and_friendships(event_df):
    filtered_df = event_df[((event_df['Date_Decision_x'] == 'Like') | (event_df['Date_Decision_x'] == 'Friendship')) &
                           ((event_df['Date_Decision_y'] == 'Like') | (event_df['Date_Decision_y'] == 'Friendship'))]
    selected_columns = ['Event_x', 'Email address_x', 'Your name_x', 'Date_Decision_x',
                        'Event_y', 'Email address_y', 'Your name_y', 'Date_Decision_y']
    return filtered_df[selected_columns]