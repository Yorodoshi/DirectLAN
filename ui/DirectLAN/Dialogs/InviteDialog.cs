using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DirectLAN.Dialogs;

internal sealed class InviteDialog : Window
{
    public InviteDialog(string token, string? expiresAt)
    {
        Title = "Одноразовое приглашение";
        Width = 500;
        SizeToContent = SizeToContent.Height;
        MinHeight = 240;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(20, 32, 51));
        Foreground = Brushes.White;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 13;

        var panel = new StackPanel { Margin = new Thickness(22) };
        panel.Children.Add(new TextBlock
        {
            Text = "Передайте этот код доверенному участнику",
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 14)
        });
        panel.Children.Add(new TextBox
        {
            Text = token,
            IsReadOnly = true,
            Padding = new Thickness(9, 7, 9, 7),
            Background = Brushes.White,
            Foreground = Brushes.Black,
            FontFamily = new FontFamily("Consolas")
        });
        panel.Children.Add(new TextBlock
        {
            Text = string.IsNullOrWhiteSpace(expiresAt)
                ? "Код одноразовый и действует ограниченное время."
                : $"Код одноразовый. Действует до: {expiresAt}",
            Foreground = new SolidColorBrush(Color.FromRgb(162, 182, 207)),
            Margin = new Thickness(0, 12, 0, 0)
        });
        panel.Children.Add(new TextBlock
        {
            Text = "При прямом подключении другой участник увидит ваш публичный IP-адрес.",
            Foreground = new SolidColorBrush(Color.FromRgb(162, 182, 207)),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 9, 0, 0)
        });

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 20, 0, 0)
        };
        var copy = new Button { Content = "Копировать код", MinWidth = 130, Margin = new Thickness(0, 0, 8, 0) };
        copy.Click += (_, _) =>
        {
            try
            {
                Clipboard.SetText(token);
                copy.Content = "Скопировано";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Не удалось скопировать код: {ex.Message}", Title,
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
        var close = new Button { Content = "Закрыть", MinWidth = 90 };
        close.Click += (_, _) => Close();
        buttons.Children.Add(copy);
        buttons.Children.Add(close);
        panel.Children.Add(buttons);
        Content = panel;
    }
}
