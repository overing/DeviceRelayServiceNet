using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Serialization;
using Emgu.CV;
using EvDevSharp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Extensions.Logging;

[assembly: SupportedOSPlatform("Linux")]

if (args.Contains("--list-device", StringComparer.OrdinalIgnoreCase))
{
    RfidReader.ListDevice();
    return;
}

var appBuilder = Host.CreateApplicationBuilder(args);

var serilogLogger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .WriteTo.File(
        path: "logs/output.log",
        outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] {Level}: {SourceContext:l} {Message:lj}{NewLine}{Exception}",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14)
    .CreateLogger();

appBuilder.Logging
    .ClearProviders()
    .AddSimpleConsole().Services
    .AddSingleton<ILoggerProvider>(_ => new SerilogLoggerProvider(serilogLogger, dispose: true));

appBuilder.Services
    .Configure<CaptureServiceOptions>(appBuilder.Configuration.GetSection(nameof(CaptureServiceOptions)))
    .AddSingleton<CaptureService>();

appBuilder.Services
    .Configure<RfidReaderOptions>(appBuilder.Configuration.GetSection(nameof(RfidReaderOptions)))
    .AddSingleton<RfidReader>();

appBuilder.Services
    .Configure<ApiClientOptions>(appBuilder.Configuration.GetSection(nameof(ApiClientOptions)))
    .AddHttpClient<ApiClient>((provider, client) =>
    {
        var options = provider.GetRequiredService<IOptions<ApiClientOptions>>();
        client.Timeout = TimeSpan.FromSeconds(options.Value.TimeoutSec);
        client.BaseAddress = options.Value.ApiUrl;
        if (options.Value.ApiKey is { Length: > 0 } apiKey)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(scheme: "Bearer", parameter: apiKey);
    });

appBuilder.Services
    .Configure<AppOption>(appBuilder.Configuration.GetSection(nameof(AppOption)))
    .AddHostedService<App>();

var app = appBuilder.Build();

await app.RunAsync();

class CaptureServiceOptions
{
    public int CameraIndex { get; set; } = 0;
    public string EncodeFormat { get; set; } = ".jpg";
}

class CaptureService
{
    readonly ILogger<CaptureService> _logger;
    readonly IOptions<CaptureServiceOptions> _options;

    public CaptureService(ILogger<CaptureService> logger, IOptions<CaptureServiceOptions> options)
    {
        (_logger, _options) = (logger, options);

        logger.LogInformation("""setup with cameta index {index}, format: {format}""", options.Value.CameraIndex, options.Value.EncodeFormat);
    }

    public byte[] Capture()
    {
        try
        {
            using var capture = new VideoCapture(camIndex: _options.Value.CameraIndex);
            if (capture.IsOpened is not true)
                throw new NotSupportedException();

            var frame = new Mat();
            if (capture.Read(frame) is not true)
                throw new NotSupportedException();

            var data = CvInvoke.Imencode(_options.Value.EncodeFormat, frame);
            _logger.LogInformation("Capture camera succeed");

            return data;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Capture camera faulted: {msg}", ex.Message);
            throw;
        }
    }
}

class RfidReaderOptions
{
    public string DeviceName { get; set; } = "USB Reader USB Reader";

    public IReadOnlyCollection<string> AllowKeyChars { get; init; } = Enumerable.Range(0, 10).Select(i => i.ToString()).ToList();
}

class RfidReader
{
    readonly ILogger<RfidReader> _logger;
    readonly IOptions<RfidReaderOptions> _options;

    readonly HashSet<EvDevKeyCode> _allowKeyCodes;

    public RfidReader(ILogger<RfidReader> logger, IOptions<RfidReaderOptions> options)
    {
        (_logger, _options) = (logger, options);
        _allowKeyCodes = options.Value.AllowKeyChars
            .Select(s => Enum.Parse<EvDevKeyCode>("KEY_" + s))
            .ToHashSet();

        logger.LogInformation("""setup with device name "{name}" """, options.Value.DeviceName);
    }

    public static void ListDevice()
    {
        var devices = EvDevDevice.GetDevices();
        foreach (var device in devices)
            Console.WriteLine($"path: {device.DevicePath}, name: {device.Name}, type: {device.GuessedDeviceType}");
    }

    EvDevDevice Connect()
    {
        _logger.LogDebug("Begin search device");
        var found = default(EvDevDevice?);
        foreach (var device in EvDevDevice.GetDevices())
        {
            _logger.LogDebug("Check devuce '{name}'", device.Name);
            if (found is null && StringComparer.Ordinal.Equals(device.Name, _options.Value.DeviceName))
            {
                _logger.LogDebug("Found device");
                found = device;
                break;
            }
        }
        if (found is null)
            throw new FileNotFoundException($"""device "{_options.Value.DeviceName}" not found""");
        return found;
    }

    public Task<string> ReadTagAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("ReadTag");
        var device = Connect();

        _logger.LogDebug("Device connected");
        var builder = new StringBuilder();

        var tcs = new TaskCompletionSource<string>();

        cancellationToken.Register(() =>
        {
            _logger.LogTrace("Set cancel");
            tcs.TrySetCanceled(cancellationToken);

            // will blocking exit process
            // _logger.LogTrace("Stop Monitoring");
            // device.StopMonitoring();

            _logger.LogTrace("Remove event");
            device.OnKeyEvent -= HandleKeyEvent;
            _logger.LogTrace("cancel token callback done");
        });

        try
        {
            device.OnKeyEvent += HandleKeyEvent;
            device.StartMonitoring();
            _logger.LogDebug("Start Monitoring");
        }
        catch (Exception ex)
        {
            tcs.TrySetException(ex);
        }

        return tcs.Task;

        void HandleKeyEvent(object _, OnKeyEventArgs args)
        {
            try
            {
                if (args.Value is not EvDevKeyValue.KeyUp)
                {
                    _logger.LogDebug("ignore with not key up: {key}", new { args.Key, args.Value });
                    return;
                }

                _logger.LogDebug("receive key: {key}", new { args.Key, args.Value });
                if (_allowKeyCodes.Contains(args.Key))
                {
                    var digi = args.Key.ToString()["KEY_".Length..];
                    _logger.LogDebug("collect key: '{digi}'", digi);
                    builder.Append(digi);
                }
                else if (args.Key == EvDevKeyCode.KEY_ENTER)
                {
                    var tag = builder.ToString();
                    builder.Clear();
                    tcs.TrySetResult(tag);
                    _logger.LogInformation("publish tag: '{tag}'", tag);

                    device.OnKeyEvent -= HandleKeyEvent;
                    device.StopMonitoring();
                    device.Dispose();
                }
                else
                    _logger.LogDebug("block key: {key} with {list}", args.Key, string.Join(", ", _allowKeyCodes));
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        }
    }
}

class ApiClientOptions
{
    public Uri ApiUrl { get; set; } = new("http://192.168.1.116:30080/api/v1/Event/");
    public string? ApiKey { get; set; } = "25B1D392-919E-4902-985C-1E980C6854AF";
    public double TimeoutSec { get; set; } = 8;
}

class ApiClient : IDisposable
{
    readonly ILogger<ApiClient> _logger;
    readonly HttpClient _httpClient;

    public ApiClient(ILogger<ApiClient> logger, IOptions<ApiClientOptions> options, HttpClient client)
    {
        (_logger, _httpClient) = (logger, client);

        logger.LogInformation("""setup with api url "{api_url}", timeout: {timeout_sec}s""", options.Value.ApiUrl, options.Value.TimeoutSec);
    }

    public async Task AliveAsync(CancellationToken cancellationToken)
    {
        try
        {
            var response = await _httpClient.PostAsync("alive", content: null, cancellationToken);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var content = await response.Content.ReadFromJsonAsync(AppJsonSerializerContext.Default.CommonResultView, cancellationToken);
                _logger.LogInformation("API alive succeed, response: {content}", content);
            }
            else
                _logger.LogError("API alive faulted, status code: {status_code}", response.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogError("API alive faulted: {msg}", ex.Message);
            _logger.LogDebug(ex, "");
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    public async Task UploadAsync(string tag, string imageDatabase64, CancellationToken cancellationToken)
    {
        try
        {
            var param = new UploadParam(RfidCode: tag, imageDatabase64);
            var response = await _httpClient.PostAsJsonAsync("upload", param, AppJsonSerializerContext.Default.UploadParam, cancellationToken);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var content = await response.Content.ReadFromJsonAsync(AppJsonSerializerContext.Default.CommonResultView, cancellationToken);
                _logger.LogInformation("API upload succeed, response: {content}", content);
            }
            else
                _logger.LogError("API upload faulted, status code: {status_code}", response.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogError("API upload faulted: {msg}", ex.Message);
            _logger.LogDebug(ex, "");
        }
    }

    public record CommonResultView(
        [property: JsonPropertyName("result")]
        string Result);

    public record UploadParam(
        [property: JsonPropertyName("rfid_code")]
        string RfidCode,
        [property: JsonPropertyName("image_data")]
        string ImageDataBase64);
}

class AppOption
{
    public double AliveIntervalSec { get; set; } = 10;
}

class App(
    ILogger<App> logger,
    IOptions<AppOption> options,
    IHostApplicationLifetime applicationLifetime,
    CaptureService captureService,
    RfidReader rfidReader,
    ApiClient apiClient)
    : BackgroundService
{
    readonly BlockingCollection<string> _tagTasks = new(boundedCapacity: 1);

    Task? _processTask;
    Task? _reportAlive;
    ManualResetEventSlim _processing = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _processTask = ProcessTaskAsync(stoppingToken);

        if (options.Value.AliveIntervalSec > 0)
            _reportAlive = ReportAliveAsync(stoppingToken);

        try
        {
            while (stoppingToken.IsCancellationRequested is not true)
            {
                logger.LogInformation("Waitting for rfid touch");
                var tag = await rfidReader.ReadTagAsync(stoppingToken);
                if (tag is { Length: > 0 } && _processing.IsSet is not true)
                {
                    logger.LogInformation("""Enqueue tag task: "{rfid_code}" """, tag);
                    _tagTasks.Add(tag, stoppingToken);
                }
            }
            _tagTasks.CompleteAdding();
        }
        catch (FileNotFoundException)
        {
            applicationLifetime.StopApplication();
            throw;
        }
        catch (TaskCanceledException)
        {
            logger.LogInformation("App main task break with TaskCanceledException");
            _tagTasks.CompleteAdding();

            logger.LogInformation("Program terminating... Waiting for tasks to finish.");
            while (_tagTasks.IsCompleted is not true)
                await Task.Yield();

            logger.LogInformation("Waiting for process to finish.");
            while (_processTask is { } process && process.IsCompleted is not true)
                await Task.Yield();

            logger.LogInformation("Waiting for alive to finish.");
            while (_reportAlive is { } alive && alive.IsCompleted is not true)
                await Task.Yield();

            logger.LogInformation("All tasks completed. Program terminated.");
        }
        catch (Exception ex)
        {
            logger.LogError("App main task occur unexpected exception, will stop host app: {msg}", ex.Message);
            logger.LogDebug(ex, "");
            applicationLifetime.StopApplication();
        }
    }

    async Task ProcessTaskAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Process task started");
        try
        {
            while (cancellationToken.IsCancellationRequested is not true)
            {
                await Task.Delay(100, cancellationToken);

                if (_tagTasks.TryTake(out var tag, 0, cancellationToken) is not true)
                    continue;

                logger.LogDebug("Will take capture");
                var captureData = captureService.Capture();

                var captureBase64 = Convert.ToBase64String(captureData);
                logger.LogDebug("Encode image data to base64");

                _processing.Reset();
                await apiClient.UploadAsync(tag, captureBase64, cancellationToken);

                logger.LogDebug("Tag task done");
            }
        }
        catch (TaskCanceledException)
        {
            logger.LogInformation("Process task break with TaskCanceledException");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Process task faulted: {msg}", ex.Message);
        }
        logger.LogInformation("Process task end");
    }

    async Task ReportAliveAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Alive task started");
        try
        {
            while (cancellationToken.IsCancellationRequested is not true)
            {
                await apiClient.AliveAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(options.Value.AliveIntervalSec), cancellationToken);
            }
        }
        catch (TaskCanceledException)
        {
            logger.LogInformation("Alive task break with TaskCanceledException");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Alive task faulted: {msg}", ex.Message);
        }
        logger.LogInformation("Alive task end");
    }
}

[JsonSerializable(typeof(ApiClient.CommonResultView))]
[JsonSerializable(typeof(ApiClient.UploadParam))]
partial class AppJsonSerializerContext : JsonSerializerContext;