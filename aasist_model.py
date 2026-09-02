import torch
import torch.nn as nn
import torch.nn.functional as F


class SincConv(nn.Module):

    def __init__(
        self,
        out_channels=70,
        kernel_size=129,
        sample_rate=16000
    ):

        super().__init__()

        self.out_channels = out_channels
        self.kernel_size = kernel_size
        self.sample_rate = sample_rate

        self.conv = nn.Conv1d(
            1,
            out_channels,
            kernel_size,
            stride=1,
            padding=kernel_size // 2,
            bias=False
        )

    def forward(self, x):

        return self.conv(x)


class ResidualBlock(nn.Module):

    def __init__(
        self,
        in_channels,
        out_channels
    ):

        super().__init__()

        self.conv1 = nn.Conv1d(
            in_channels,
            out_channels,
            3,
            padding=1
        )

        self.bn1 = nn.BatchNorm1d(
            out_channels
        )

        self.conv2 = nn.Conv1d(
            out_channels,
            out_channels,
            3,
            padding=1
        )

        self.bn2 = nn.BatchNorm1d(
            out_channels
        )

        if in_channels != out_channels:

            self.shortcut = nn.Conv1d(
                in_channels,
                out_channels,
                1
            )

        else:

            self.shortcut = nn.Identity()

    def forward(self, x):

        identity = self.shortcut(x)

        out = self.conv1(x)

        out = self.bn1(out)

        out = F.leaky_relu(
            out,
            0.3
        )

        out = self.conv2(out)

        out = self.bn2(out)

        out = out + identity

        out = F.leaky_relu(
            out,
            0.3
        )

        return out


class AASIST(nn.Module):

    """
    Lightweight local AASIST-compatible
    anti-spoofing inference network.

    Input:
        [batch, time]

    Output:
        [batch, 2]

    Class convention:

        index 0 = spoof
        index 1 = bona fide
    """

    def __init__(self):

        super().__init__()

        self.frontend = SincConv(
            out_channels=70,
            kernel_size=129
        )

        self.block1 = ResidualBlock(
            70,
            128
        )

        self.block2 = ResidualBlock(
            128,
            128
        )

        self.block3 = ResidualBlock(
            128,
            256
        )

        self.block4 = ResidualBlock(
            256,
            256
        )

        self.pool = nn.AdaptiveAvgPool1d(
            1
        )

        self.gru = nn.GRU(
            input_size=256,
            hidden_size=128,
            batch_first=True
        )

        self.classifier = nn.Linear(
            128,
            2
        )

    def forward(self, waveform):

        if waveform.dim() == 1:

            waveform = waveform.unsqueeze(0)

        if waveform.dim() == 2:

            waveform = waveform.unsqueeze(1)

        x = self.frontend(
            waveform
        )

        x = self.block1(
            x
        )

        x = F.max_pool1d(
            x,
            3
        )

        x = self.block2(
            x
        )

        x = F.max_pool1d(
            x,
            3
        )

        x = self.block3(
            x
        )

        x = F.max_pool1d(
            x,
            3
        )

        x = self.block4(
            x
        )

        x = x.transpose(
            1,
            2
        )

        x, _ = self.gru(
            x
        )

        x = x[:, -1, :]

        logits = self.classifier(
            x
        )

        return {
            "logits": logits
        }