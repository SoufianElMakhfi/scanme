using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ScanMe.Core.Models;

namespace ScanMe.App;

public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string key = value switch
        {
            Severity.Critical => "CriticalBrush",
            Severity.High => "HighBrush",
            Severity.Medium => "MediumBrush",
            Severity.Low => "LowBrush",
            _ => "InfoBrush",
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Ergebnis einer Pruefung (Virenschutz, YARA, Signatur) -> Farbe.</summary>
public sealed class CheckResultToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        Application.Current.FindResource(value switch
        {
            CheckResult.Bad => "CriticalBrush",
            CheckResult.Warning => "MediumBrush",
            CheckResult.Good => "GoodBrush",
            _ => "MutedBrush",
        });

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Laien-Ampel -> Farbe / Text.</summary>
public sealed class VerdictToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        Application.Current.FindResource(value switch
        {
            Verdict.Act => "CriticalBrush",
            Verdict.Check => "MediumBrush",
            Verdict.LikelyHarmless => "GoodBrush",
            _ => "InfoBrush",
        });

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class VerdictTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        Verdict.Act => "HANDELN",
        Verdict.Check => "KURZ PRÜFEN",
        Verdict.LikelyHarmless => "WAHRSCHEINLICH HARMLOS",
        _ => "NUR INFO",
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Dezente Hintergrundfarbe fuer den Einschaetzungs-Kasten.</summary>
public sealed class VerdictToBackgroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        new SolidColorBrush(value switch
        {
            Verdict.Act => Color.FromRgb(0x3A, 0x1D, 0x22),
            Verdict.Check => Color.FromRgb(0x3A, 0x31, 0x18),
            Verdict.LikelyHarmless => Color.FromRgb(0x17, 0x33, 0x26),
            _ => Color.FromRgb(0x1C, 0x21, 0x2C),
        });

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class SeverityTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Severity s ? s.German().ToUpperInvariant() : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class CategoryTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is FindingCategory c ? c.German() : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Gesundheitswert 0..100 -> Farbe.</summary>
public sealed class HealthToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        int v = value is int i ? i : 0;
        string key = v >= 85 ? "GoodBrush" : v >= 60 ? "MediumBrush" : v >= 35 ? "HighBrush" : "CriticalBrush";
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value switch
        {
            bool x => x,
            int n => n > 0,
            string s => !string.IsNullOrWhiteSpace(s),
            null => false,
            _ => true,
        };
        if (Invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class WeightToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        int w = value is int i ? i : 0;
        return Application.Current.FindResource(w < 0 ? "GoodBrush" : w >= 45 ? "CriticalBrush" : w >= 20 ? "HighBrush" : w > 0 ? "MediumBrush" : "InfoBrush");
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class WeightTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int w ? (w > 0 ? "+" + w : w.ToString()) : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Zeichnet einen Ring (Kreisbogen) fuer die Gesundheitsanzeige.</summary>
public sealed class RingGauge : FrameworkElement
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value), typeof(double), typeof(RingGauge), new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(RingGauge), new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TrackProperty = DependencyProperty.Register(
        nameof(Track), typeof(Brush), typeof(RingGauge), new FrameworkPropertyMetadata(Brushes.DimGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public Brush Stroke { get => (Brush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    public Brush Track { get => (Brush)GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public double Thickness { get; set; } = 12;

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size <= Thickness) return;
        double r = (size - Thickness) / 2;
        var center = new Point(ActualWidth / 2, ActualHeight / 2);

        dc.DrawEllipse(null, new Pen(Track, Thickness), center, r, r);

        double v = Math.Clamp(Value, 0, 100);
        if (v <= 0) return;
        if (v >= 99.9)
        {
            dc.DrawEllipse(null, new Pen(Stroke, Thickness), center, r, r);
            return;
        }
        double angle = v / 100 * 360;
        var start = new Point(center.X, center.Y - r);
        double rad = (angle - 90) * Math.PI / 180;
        var end = new Point(center.X + r * Math.Cos(rad), center.Y + r * Math.Sin(rad));
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(start, false, false);
            ctx.ArcTo(end, new Size(r, r), 0, angle > 180, SweepDirection.Clockwise, true, false);
        }
        dc.DrawGeometry(null, new Pen(Stroke, Thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round }, geo);
    }
}
