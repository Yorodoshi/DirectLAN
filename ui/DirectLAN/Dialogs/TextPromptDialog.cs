using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DirectLAN.Dialogs;

internal sealed class TextPromptDialog : Window
{
    private readonly TextBox _input;

    public string Value => _input.Text.Trim();

    public TextPromptDialog(string title, string label, string? note = null, string initialValue = "")
    {
        Title = title;
        Width = 460;
        SizeToContent = SizeToContent.Height;
        MinHeight = 210;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(20, 32, 51));
        Foreground = Brushes.White;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 13;

        var panel = new StackPanel { Margin = new Thickness(22) };
        panel.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12)
        });

        _input = new TextBox
        {
            Text = initialValue,
            MinHeight = 34,
            Padding = new Thickness(8, 6, 8, 6),
            Background = Brushes.White,
            Foreground = Brushes.Black
        };
        _input.KeyDown += (_, e) =>
        {
            if (e.Key == System.Windows.Input.Key.Enter)
            {
                Confirm();
            }
        };
        panel.Children.Add(_input);

        if (!string.IsNullOrWhiteSpace(note))
        {
            panel.Children.Add(new TextBlock
            {
                Text = note,
                Foreground = new SolidColorBrush(Color.FromRgb(162, 182, 207)),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 12, 0, 0)
            });
        }

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 20, 0, 0)
        };
        var cancel = new Button { Content = "Отмена", MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        cancel.Click += (_, _) => DialogResult = false;
        var confirm = new Button { Content = "Продолжить", MinWidth = 100 };
        confirm.Click += (_, _) => Confirm();
        buttons.Children.Add(cancel);
        buttons.Children.Add(confirm);
        panel.Children.Add(buttons);
        Content = panel;
        Loaded += (_, _) =>
        {
            _input.Focus();
            _input.SelectAll();
        };
    }

    private void Confirm()
    {
        if (Value.Length == 0)
        {
            MessageBox.Show(this, "Введите значение.", Title, MessageBoxButton.OK,
                MessageBoxImage.Information);
            _input.Focus();
            return;
        }

        DialogResult = true;
    }
}
