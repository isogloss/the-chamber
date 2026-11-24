using System.Windows;

namespace TheChamber.Views;

public partial class SplashWindow : Window
{
    public SplashWindow()
    {
        InitializeComponent();
    }

    public void SetStatus(string text)
    {
        // Can be called from any task-continuation thread; Dispatcher
        // handles the marshal.
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => SetStatus(text));
            return;
        }
        StatusText.Text = text.ToLowerInvariant();
    }
}
